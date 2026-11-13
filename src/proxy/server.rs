//! Server functions for running proxy port listeners and channel servers

use axum::{
    Router,
    http::{HeaderValue, request::Parts as RequestParts},
};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tracing::{debug, error, info, warn};

use crate::config::GatewayConfig;
use crate::observability::loggable;
use crate::state::{MultiSurfaceProxyState, SurfaceInfo};

// ── Credential delegation global stores ──────────────────────────────────────
// Follows the same OnceLock pattern used for trust_registry_listener_manager
// in gateways/connection_points/message_processor.rs

static GLOBAL_CREDENTIAL_PROVIDER_STORE: OnceLock<
    Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>,
> = OnceLock::new();
static GLOBAL_DELEGATION_VAULT_STORE: OnceLock<Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>> =
    OnceLock::new();
static GLOBAL_GATEWAY_BASE_URL: OnceLock<String> = OnceLock::new();
static GLOBAL_TRANSIT_TOKEN_ISSUER: OnceLock<Arc<crate::proxy::transit_token::TransitTokenIssuer>> = OnceLock::new();
static GLOBAL_CERTIFICATES_STORE: OnceLock<Arc<dyn crate::certificates::CertificateStore>> = OnceLock::new();

fn parse_cors_origins(cors_origins: &[String]) -> Arc<Vec<HeaderValue>> {
    Arc::new(
        cors_origins
            .iter()
            .filter_map(|origin| match origin.parse::<HeaderValue>() {
                Ok(value) => Some(value),
                Err(error) => {
                    warn!(origin = %origin, error = %error, "Ignoring invalid CORS origin in network config");
                    None
                }
            })
            .collect(),
    )
}

/// Any origin may read a public discovery document (`GET`/`HEAD` of a public
/// path); every other request, including a `POST` to a path that only ends
/// like one, needs an allowlisted origin. `method` is the method the request
/// will use: for a preflight, its `Access-Control-Request-Method`.
fn is_proxy_cors_origin_allowed(
    origin: &HeaderValue,
    method: &str,
    path: &str,
    origins: &[HeaderValue],
) -> bool {
    if crate::proxy::paths::is_public_request(method, path) {
        return true;
    }

    if origins.is_empty() {
        return false;
    }

    debug!("Checking proxy CORS origin: {:?} against allowed origins: {:?}", origin, origins);
    origins.contains(origin)
}

/// The method a request will use: a preflight's requested method, else its own.
fn cors_request_method(request_parts: &RequestParts) -> String {
    if request_parts.method == axum::http::Method::OPTIONS
        && let Some(requested) = request_parts
            .headers
            .get(axum::http::header::ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(|value| value.to_str().ok())
    {
        return requested.to_string();
    }
    request_parts
        .method
        .as_str()
        .to_string()
}

fn proxy_cors_layer(cors_origins: &[String]) -> CorsLayer {
    cors_layer(cors_origins, false, None)
}

/// CORS for the routes of surfaces: `network.cors` plus, for a path that
/// belongs to a surface, that surface's `browser_origins`, read from `surfaces`
/// on every request so a saved change applies at once.
fn surface_cors_layer(
    cors_origins: &[String],
    surfaces: &Arc<RwLock<Vec<SurfaceInfo>>>,
) -> CorsLayer {
    cors_layer(cors_origins, false, Some(Arc::clone(surfaces)))
}

/// Whether `origin` is one of the `browser_origins` of the active surface that
/// `path` belongs to.
async fn is_surface_browser_origin(
    surfaces: &RwLock<Vec<SurfaceInfo>>,
    origin: &HeaderValue,
    path: &str,
) -> bool {
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let surfaces = surfaces.read().await;
    super::handler::match_surface_route(&surfaces, path).is_some_and(|(info, ..)| {
        info.surface.status == crate::config::agent_surface::SurfaceStatus::Active
            && info
                .surface
                .browser_origins
                .iter()
                .any(|allowed| allowed == origin)
    })
}

/// Removes every `Set-Cookie` and `Set-Cookie2` from an Access Point's answer.
/// The target shares the caller-facing host with the gateway's dashboard, so a
/// cookie it sets would land on the dashboard's origin; and the caller's
/// cookies are never forwarded to it, so a cookie it sets could never come back.
async fn withhold_target_cookies(mut response: axum::response::Response) -> axum::response::Response {
    let headers = response.headers_mut();
    headers.remove(axum::http::header::SET_COOKIE);
    headers.remove("set-cookie2");
    response
}

/// CORS for protected resource metadata: browser MCP clients on any origin
/// read it with `GET` or `HEAD`, and other methods keep the `cors` allowlist.
/// It is layered on the metadata routes only, and only on a listener where no
/// channel or proxy route also receives these paths, so a proxied Target's
/// responses are never opened to every origin.
fn metadata_cors_layer(cors_origins: &[String]) -> CorsLayer {
    cors_layer(cors_origins, true, None)
}

fn cors_layer(
    cors_origins: &[String],
    any_origin_reads: bool,
    surfaces: Option<Arc<RwLock<Vec<SurfaceInfo>>>>,
) -> CorsLayer {
    let origins = parse_cors_origins(cors_origins);

    CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(AllowOrigin::async_predicate(move |origin: HeaderValue, request_parts: &RequestParts| {
            let origins = Arc::clone(&origins);
            let surfaces = surfaces.clone();
            let path = request_parts
                .uri
                .path()
                .to_string();
            let method = cors_request_method(request_parts);
            let reads = method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD");
            async move {
                if any_origin_reads && reads || is_proxy_cors_origin_allowed(&origin, &method, &path, &origins) {
                    return true;
                }
                match surfaces {
                    Some(surfaces) => is_surface_browser_origin(&surfaces, &origin, &path).await,
                    None => false,
                }
            }
        }))
        .allow_headers(Any)
        // A browser MCP client reads the 401 challenge to find the metadata.
        .expose_headers([axum::http::header::WWW_AUTHENTICATE])
}

pub fn init_certificates_store(store: Arc<dyn crate::certificates::CertificateStore>) {
    let _ = GLOBAL_CERTIFICATES_STORE.set(store);
    info!(target: "certificates", "Global certificate store initialized for proxy pipeline");
}

pub fn get_certificates_store() -> Option<Arc<dyn crate::certificates::CertificateStore>> {
    GLOBAL_CERTIFICATES_STORE
        .get()
        .cloned()
}

pub fn init_credential_delegation_stores(
    provider_store: Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>,
    vault_store: Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>,
    base_url: String,
) {
    let _ = GLOBAL_CREDENTIAL_PROVIDER_STORE.set(provider_store);
    let _ = GLOBAL_DELEGATION_VAULT_STORE.set(vault_store);
    let _ = GLOBAL_GATEWAY_BASE_URL.set(base_url);
    info!(target: "credential_delegation", "Global credential delegation stores initialized for proxy pipeline");
}

pub fn get_credential_provider_store()
-> Option<Arc<dyn crate::credential_providers::storage::CredentialProviderStorage>> {
    GLOBAL_CREDENTIAL_PROVIDER_STORE
        .get()
        .cloned()
}

pub fn get_delegation_vault_store() -> Option<Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>> {
    GLOBAL_DELEGATION_VAULT_STORE
        .get()
        .cloned()
}

pub fn get_gateway_base_url() -> Option<String> {
    GLOBAL_GATEWAY_BASE_URL
        .get()
        .cloned()
}

/// Install the process-wide transit token issuer. The first issuer installed
/// stays in use; a later one is ignored with a warning.
pub fn init_transit_token_issuer(issuer: Arc<crate::proxy::transit_token::TransitTokenIssuer>) {
    if GLOBAL_TRANSIT_TOKEN_ISSUER
        .set(issuer)
        .is_err()
    {
        warn!(target: "transit_token", "Global transit token issuer is already initialized; keeping the first one");
        return;
    }
    info!(target: "transit_token", "Global transit token issuer initialized for proxy pipeline");
}

pub fn get_transit_token_issuer() -> Option<Arc<crate::proxy::transit_token::TransitTokenIssuer>> {
    GLOBAL_TRANSIT_TOKEN_ISSUER
        .get()
        .cloned()
}

/// Build the AP `listen_address` shown in the Tasks UI by appending the
/// surface route to the listener host. Returns `"fabric"` for fabric-only
/// surfaces (empty host).
pub(crate) fn join_host_and_route(
    host: &str,
    route: &str,
) -> String {
    if host.is_empty() {
        return if route.is_empty() || route == "/" {
            "fabric".to_string()
        } else if route.starts_with('/') {
            format!("fabric{}", route)
        } else {
            format!("fabric/{}", route)
        };
    }
    let host_trim = host.trim_end_matches('/');
    if route.is_empty() || route == "/" {
        host_trim.to_string()
    } else if route.starts_with('/') {
        format!("{}{}", host_trim, route)
    } else {
        format!("{}/{}", host_trim, route)
    }
}

/// The host of a URL string, without its port, in lower case and in the form the
/// URL parser normalises it to: an IPv6 address in brackets and compressed, so
/// `[2001:DB8:0::1]` and `[2001:db8::1]` are the same host. `None` for a URL
/// that does not parse or has no host.
fn extract_hostname(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .host_str()
        .map(str::to_ascii_lowercase)
}

/// Find the first outbound listener whose external URLs share a hostname with
/// the inbound listener on `inbound_port`. Returns `None` when no overlap exists
/// (i.e. inbound and outbound have fully separate domains).
///
/// Used by `build_port_router` to decide whether to register the `/outbound/*`
/// reverse-proxy on the inbound port.
pub(crate) fn find_shared_outbound_listener(
    network_config: &crate::config::NetworkConfig,
    inbound_port: u16,
) -> Option<&crate::config::network::Listener> {
    let inbound_hostnames: std::collections::HashSet<String> = network_config
        .listeners
        .iter()
        .filter(|l| l.listener_type == "inbound" && l.port == inbound_port)
        .flat_map(|l| l.external_urls.iter())
        .filter_map(|url| extract_hostname(url))
        .collect();

    network_config
        .listeners
        .iter()
        .filter(|l| l.listener_type == "outbound")
        .find(|l| {
            l.external_urls
                .iter()
                .filter_map(|url| extract_hostname(url))
                .any(|h| inbound_hostnames.contains(&h))
        })
}

/// Whether the inbound listener's `/outbound` proxy passes `header` to the
/// outbound listener: every header but hop-by-hop ones, `host`, and the
/// forwarded client certificate header. The outbound listener sees this
/// gateway as the peer, so it would take a certificate in that header, which
/// this hop never verified, as one a trusted proxy forwarded. Unlike
/// `should_forward_request_header` it keeps `x-transit-token`, which the
/// Transit Point checks.
fn shared_domain_proxy_forwards(
    header: &str,
    forwarded_cert_header: &str,
) -> bool {
    let header = header.to_ascii_lowercase();
    !crate::a2a::is_hop_by_hop_header(&header)
        && header != "host"
        && !header.eq_ignore_ascii_case(forwarded_cert_header)
}

/// The longest the shared-host hop waits on a read from the outbound listener:
/// the largest stream idle timeout and stream lifetime a surface can set,
/// 86400 seconds.
const SHARED_HOST_HOP_READ_IDLE: std::time::Duration = std::time::Duration::from_secs(86_400);

/// How far past `max_body_bytes` the hop streams a body without a declared
/// length before it stops. More than hyper's largest write buffer (about
/// 400 KiB), so the outbound listener has read past its own cap, refused the
/// request and recorded the refusal before the hop aborts the connection.
pub(crate) const SHARED_HOST_HOP_STREAM_MARGIN: usize = 512 * 1024;

/// The shared-host `/outbound` hop: where it forwards, and the largest request
/// body it passes on.
pub(crate) struct SharedHostHop {
    pub(crate) target: String,
    pub(crate) client: reqwest::Client,
    pub(crate) forwarded_cert_header: String,
    pub(crate) max_body_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HopBodyFault {
    TooLarge,
    ReadFailed,
}

/// The request body as a stream that records once more than `max_bytes` have
/// been read, passes on the chunk that takes it past `max_bytes` plus
/// [`SHARED_HOST_HOP_STREAM_MARGIN`] and fails on the next poll without reading
/// further, and fails and records when the caller's body fails. So it reads at
/// most `max_bytes` plus the margin plus one chunk.
fn capped_hop_body(
    body: axum::body::Body,
    max_bytes: usize,
    fault: Arc<OnceLock<HopBodyFault>>,
) -> impl futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send + 'static {
    use futures::StreamExt;
    let stop_after = max_bytes.saturating_add(SHARED_HOST_HOP_STREAM_MARGIN);
    let mut chunks = body.into_data_stream();
    let mut read = 0usize;
    let mut ended = false;
    futures::stream::poll_fn(move |cx| {
        if ended {
            return std::task::Poll::Ready(None);
        }
        if read > stop_after {
            ended = true;
            return std::task::Poll::Ready(Some(Err(std::io::Error::other(
                "request body exceeds the shared-host hop limit",
            ))));
        }
        match std::task::ready!(chunks.poll_next_unpin(cx)) {
            Some(Ok(bytes)) => {
                read = read.saturating_add(bytes.len());
                if read > max_bytes {
                    let _ = fault.set(HopBodyFault::TooLarge);
                }
                std::task::Poll::Ready(Some(Ok(bytes)))
            }
            Some(Err(error)) => {
                ended = true;
                let _ = fault.set(HopBodyFault::ReadFailed);
                std::task::Poll::Ready(Some(Err(std::io::Error::other(error))))
            }
            None => std::task::Poll::Ready(None),
        }
    })
}

/// The hop's own 413 for a body over the cap, or 400 for one the caller failed
/// to send: a JSON-RPC error for an MCP caller, an A2A problem otherwise.
fn hop_refusal(
    fault: HopBodyFault,
    mcp: bool,
    max_bytes: usize,
) -> axum::response::Response {
    match (fault, mcp) {
        (HopBodyFault::TooLarge, true) => crate::mcp::modern_http::body_too_large_response(),
        (HopBodyFault::TooLarge, false) => crate::proxy::body_too_large_response(max_bytes),
        (HopBodyFault::ReadFailed, true) => crate::mcp::modern_http::body_read_failed_response(),
        (HopBodyFault::ReadFailed, false) => {
            crate::a2a::create_error_response(axum::http::StatusCode::BAD_REQUEST, "Failed to read request body")
        }
    }
}

/// Forwards a request on the inbound listener to the outbound listener that
/// shares its host. The body is streamed, never buffered, so the outbound
/// listener authenticates the caller before it is read. A declared length over
/// `max_body_bytes` is refused with 413 without reading. A longer body is
/// streamed until the outbound listener answers, at most to `max_body_bytes`
/// plus [`SHARED_HOST_HOP_STREAM_MARGIN`]; when its answer is lost the hop
/// answers 413 itself. One the caller fails to send is refused with 400, never
/// forwarded empty. The response is streamed back.
pub(crate) async fn forward_shared_host_hop(
    hop: Arc<SharedHostHop>,
    req: axum::extract::Request,
) -> axum::response::Response {
    use axum::body::HttpBody;
    let caller = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map_or_else(|| "unknown".to_string(), |info| info.0.to_string());
    let mcp = req
        .headers()
        .contains_key("mcp-protocol-version");
    let declared_length = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let path = req.uri().path().to_string();
    if declared_length.is_some_and(|length| length > hop.max_body_bytes as u64) {
        warn!(
            caller = %caller,
            path = %path,
            max = hop.max_body_bytes,
            "Shared-host hop refused a declared oversize body"
        );
        return hop_refusal(HopBodyFault::TooLarge, mcp, hop.max_body_bytes);
    }
    let url = format!(
        "{}{}",
        hop.target,
        req.uri()
            .path_and_query()
            .map_or("/", |pq| pq.as_str())
    );
    let mut builder = hop
        .client
        .request(req.method().clone(), &url);
    for (key, value) in req.headers() {
        if shared_domain_proxy_forwards(key.as_str(), &hop.forwarded_cert_header)
            && let Ok(v) = value.to_str()
        {
            builder = builder.header(key.as_str(), v);
        }
    }
    let fault = Arc::new(OnceLock::new());
    if !req.body().is_end_stream() {
        builder = builder.body(reqwest::Body::wrap_stream(capped_hop_body(
            req.into_body(),
            hop.max_body_bytes,
            fault.clone(),
        )));
    }

    match builder.send().await {
        Ok(resp) => {
            let status =
                axum::http::StatusCode::from_u16(resp.status().as_u16()).unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
            let mut response_builder = axum::response::Response::builder().status(status);
            for (key, value) in resp.headers() {
                if !crate::a2a::is_hop_by_hop_header(key.as_str()) {
                    response_builder = response_builder.header(key.as_str(), value.as_bytes());
                }
            }
            response_builder
                .body(axum::body::Body::from_stream(resp.bytes_stream()))
                .unwrap_or_else(|_| {
                    axum::response::Response::builder()
                        .status(axum::http::StatusCode::BAD_GATEWAY)
                        .body(axum::body::Body::empty())
                        .unwrap()
                })
        }
        Err(e) => match fault.get() {
            Some(HopBodyFault::TooLarge) if (e.is_body() || e.is_request()) && !e.is_timeout() => {
                warn!(caller = %caller, path = %path, max = hop.max_body_bytes, "Shared-host hop refused an oversize body");
                hop_refusal(HopBodyFault::TooLarge, mcp, hop.max_body_bytes)
            }
            Some(HopBodyFault::ReadFailed) => {
                warn!(caller = %caller, path = %path, "Shared-host hop could not read the caller's body");
                hop_refusal(HopBodyFault::ReadFailed, mcp, hop.max_body_bytes)
            }
            _ => {
                if (e.is_body() || e.is_request()) && !e.is_connect() {
                    debug!(error = %e.without_url(), url = %loggable::url(&url), "Outgoing proxy forward failed");
                } else {
                    warn!(error = %e.without_url(), url = %loggable::url(&url), "Outgoing proxy forward failed");
                }
                axum::response::Response::builder()
                    .status(axum::http::StatusCode::BAD_GATEWAY)
                    .body(axum::body::Body::empty())
                    .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
            }
        },
    }
}

/// Whether callers on other hosts can use `url`: its host is not `localhost`
/// or a loopback or unspecified address. A private or link-local address
/// counts, as every workload on that network reaches it; so does any other
/// host name, and a URL that does not parse.
fn reachable_from_other_hosts(url: &str) -> bool {
    let Some(host) = url::Url::parse(url)
        .ok()
        .and_then(|url| {
            url.host()
                .map(|host| host.to_owned())
        })
    else {
        return true;
    };
    let this_host = |ip: std::net::IpAddr| {
        let ip = ip.to_canonical();
        ip.is_loopback() || ip.is_unspecified()
    };
    match host {
        url::Host::Domain(name) => name != "localhost" && !name.ends_with(".localhost"),
        url::Host::Ipv4(ip) => !this_host(ip.into()),
        url::Host::Ipv6(ip) => !this_host(ip.into()),
    }
}

/// The listener itself as `address:port` when it binds an address other hosts
/// reach, which is any but loopback; a `bind_address` that does not parse
/// counts too.
fn exposed_bind_address(listener: &crate::config::network::Listener) -> Option<String> {
    match crate::config::network::parse_bind_address(&listener.bind_address) {
        Ok(ip)
            if ip
                .to_canonical()
                .is_loopback() =>
        {
            None
        }
        Ok(ip) => Some(std::net::SocketAddr::new(ip, listener.port).to_string()),
        Err(_) => Some(format!("{}:{}", listener.bind_address, listener.port)),
    }
}

/// Where callers on other hosts reach the outbound listener on `port`: its own
/// external URLs and those of every inbound listener that passes `/outbound`
/// requests to it because the two share a host name, when such a URL is
/// [`reachable_from_other_hosts`], and the bind address of each of those
/// listeners that binds beyond loopback.
pub(crate) fn exposed_outbound_addresses(
    network_config: &crate::config::NetworkConfig,
    port: u16,
) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    network_config
        .listeners
        .iter()
        .filter(|listener| {
            (listener.listener_type == "outbound" && listener.port == port)
                || (listener.listener_type == "inbound"
                    && find_shared_outbound_listener(network_config, listener.port)
                        .is_some_and(|outbound| outbound.port == port))
        })
        .flat_map(|listener| {
            listener
                .external_urls
                .iter()
                .filter(|url| reachable_from_other_hosts(url))
                .cloned()
                .chain(exposed_bind_address(listener))
        })
        .filter(|address| seen.insert(address.clone()))
        .collect()
}

/// A Transit Point that serves callers it does not authenticate
/// (`allow_unauthenticated_callers`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OpenTransitPoint {
    pub alias: String,
    /// The variant whose overrides define this Transit Point; `None` for the
    /// surface's own.
    pub variant: Option<String>,
    /// The outbound listener it is served on, when its address resolves to one.
    pub port: Option<u16>,
    /// Where callers on other hosts reach it ([`exposed_outbound_addresses`]).
    pub exposed_at: Vec<String>,
}

impl OpenTransitPoint {
    /// What an operator is told about it when other hosts can reach it.
    pub fn exposure(&self) -> Option<String> {
        if self.exposed_at.is_empty() {
            return None;
        }
        let variant = self
            .variant
            .as_deref()
            .map(|variant| format!(" in variant '{variant}'"))
            .unwrap_or_default();
        Some(format!(
            "Transit Point '{}'{variant} serves callers it does not authenticate and is reachable from other \
             hosts: {}",
            self.alias,
            self.exposed_at.join(", ")
        ))
    }
}

/// The Transit Points of `surface`, and those its variants define, that serve
/// callers they do not authenticate.
pub(crate) fn open_transit_points(
    network_config: &crate::config::NetworkConfig,
    surface: &crate::config::agent_surface::AgentSurface,
) -> Vec<OpenTransitPoint> {
    let Some(transit) = surface.transit.as_ref() else {
        return Vec::new();
    };
    let port_of = |address: Option<&str>| {
        address.and_then(|address| network_config.map_url_to_port_for_type(address, Some("outbound")))
    };
    let surface_port = port_of(
        transit
            .outbound_listen_address
            .as_deref(),
    );
    let variant_points = surface
        .variants
        .iter()
        .flat_map(|variant| {
            variant
                .overrides
                .transit
                .iter()
                .filter_map(|transit| transit.points.as_ref())
                .flatten()
                .map(move |point| (Some(variant.alias.clone()), point))
        });
    transit
        .points
        .iter()
        .map(|point| (None, point))
        .chain(variant_points)
        .filter(|(_, point)| point.allow_unauthenticated_callers && !point.authenticates_callers())
        .map(|(variant, point)| {
            let port = port_of(
                point
                    .listen_address
                    .as_deref(),
            )
            .or(surface_port);
            OpenTransitPoint {
                alias: point.alias.clone(),
                variant,
                port,
                exposed_at: port
                    .map(|port| exposed_outbound_addresses(network_config, port))
                    .unwrap_or_default(),
            }
        })
        .collect()
}

/// The non-root prefixes the identity API is mounted at, without a trailing `/`.
fn identity_api_prefixes(network_config: &crate::config::NetworkConfig) -> Vec<String> {
    network_config
        .routes
        .values()
        .filter(|route| route.route_type == crate::config::RouteType::IdentityApi)
        .map(|route| {
            route
                .prefix
                .trim_end_matches('/')
                .to_string()
        })
        .filter(|prefix| !prefix.is_empty())
        .collect()
}

/// A static site at `static_path`, answering every path it has no file for with its
/// `index.html`, under the dashboard's cache and security headers.
fn static_site(static_path: &str) -> Router {
    with_static_site_headers(static_files(static_path))
}

fn static_files(static_path: &str) -> Router {
    Router::new().fallback_service(
        tower_http::services::ServeDir::new(static_path)
            .append_index_html_on_directories(true)
            .fallback(tower_http::services::ServeFile::new(format!("{}/index.html", static_path))),
    )
}

/// `router` under the cache and security headers of the dashboard's static files, each set only
/// where the response has none.
fn with_static_site_headers(router: Router) -> Router {
    use hyper::header::CACHE_CONTROL;
    use hyper::http::HeaderValue;
    use tower_http::set_header::SetResponseHeaderLayer;

    router
        .layer(SetResponseHeaderLayer::if_not_present(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=3600, must-revalidate"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("frame-ancestors 'none'"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
}

/// The dashboard SPA, served for every path no route matched, except a path at or below an
/// identity API prefix: no API route answers it, so it is a `404`, not the dashboard page.
fn dashboard_fallback(
    static_path: &str,
    api_prefixes: Vec<String>,
) -> Router {
    let api_prefixes = Arc::new(api_prefixes);
    with_static_site_headers(static_files(static_path).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let api_prefixes = api_prefixes.clone();
            async move {
                use axum::response::IntoResponse;
                let path = request.uri().path();
                let under_api = api_prefixes
                    .iter()
                    .any(|prefix| {
                        path.strip_prefix(prefix.as_str())
                            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
                    });
                if under_api {
                    return (
                        axum::http::StatusCode::NOT_FOUND,
                        [(axum::http::header::CACHE_CONTROL, "no-store")],
                        axum::Json(serde_json::json!({"error": "Not found"})),
                    )
                        .into_response();
                }
                next.run(request).await
            }
        },
    )))
}

/// Build the router of the inbound listener on `port`, which serves every
/// surface on that port, with the MultiSurfaceProxyState its routes share so
/// those surfaces can be updated in place. Binding the port is left to the
/// caller, so a rebuilt router can replace the one a bound listener serves.
pub async fn build_port_router(
    port: u16,
    surfaces: Vec<crate::config::agent_surface::AgentSurface>,
    _tls_acceptor: TlsAcceptor,
    client: reqwest::Client,
    config: Arc<GatewayConfig>,
    bootstrap_config: Arc<crate::config::BootstrapConfig>,
    metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
    task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    ws_state: Option<Arc<crate::server::WsState>>,
    vc_issuer: Option<Arc<crate::identity::VCIssuer>>,
    listener_manager: Arc<tokio::sync::RwLock<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>>,
    identity_api_router: Option<axum::Router>,
    onboarding_router: Option<axum::Router>,
    did_router: Option<axum::Router>,
    secrets_router: Option<axum::Router>,
    secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
    network_config: Arc<crate::config::NetworkConfig>,
    policy_manager: Option<Arc<crate::policies::SurfacePolicyManager>>,
    gateway_policy_manager: Option<Arc<crate::policies::GatewayPolicyManager>>,
    mcp_proxy_store: Option<Arc<crate::mcp_proxies::FileSystemMcpProxyStore>>,
    a2a_proxy_store: Option<Arc<crate::a2a_proxies::FileSystemA2aProxyStore>>,
    mcp_server_manager: Option<Arc<crate::mcp_proxies::handlers::McpServerManager>>,
    _settings_store: Arc<crate::storage::SettingsStore>,
    _notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    didauth_session_store: Arc<crate::didauth::DidAuthSessionStore>,
    source_auth_middleware: Option<Arc<crate::source_auth::SourceAuthMiddleware>>,
    resolved_surface_cache: Arc<crate::surfaces::ResolvedSurfaceCache>,
    #[cfg(feature = "didwebvh")] didwebvh_identity_store: Option<
        Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>,
    >,
    #[cfg(feature = "didwebvh")] didwebvh_log_storage: Option<Arc<dyn crate::storage::DidLogStorage>>,
) -> anyhow::Result<(Router, Arc<MultiSurfaceProxyState>)> {
    info!("Building the port listener router on port {} for {} channel(s)", port, surfaces.len());

    // Build channel info for each channel on this port
    let mut channel_infos = Vec::new();

    for surface in surfaces.iter() {
        let channel_surface = surface.clone();
        let surface_name = channel_surface.name.clone();
        let surface_config_id: Option<String> = channel_surface
            .config_id()
            .map(|s| s.to_string());
        let surface_listen_address = channel_surface
            .listen_address()
            .to_string();
        let surface_route = channel_surface
            .route()
            .to_string();
        let surface_target_endpoint = channel_surface
            .target_endpoint()
            .to_string();

        // VALIDATION: when `default_variant_id` IS set, it must reference
        // one of the variants. `None` is allowed even with a non-empty
        // `variants[]` — semantics: alias-less URLs resolve to the bare
        // base surface (the implicit "base" default).
        if !channel_surface
            .variants
            .is_empty()
            && let Some(default_id) = channel_surface
                .default_variant_id
                .as_ref()
            && !channel_surface
                .variants
                .iter()
                .any(|v| &v.id == default_id)
        {
            let error_msg = format!(
                "CONFIGURATION ERROR: Surface '{}' (config_id: {:?}) has default_variant_id='{}' but no variant with that ID exists. \
                Available variant IDs: {:?}",
                surface_name,
                surface_config_id,
                default_id,
                channel_surface
                    .variants
                    .iter()
                    .map(|v| &v.id)
                    .collect::<Vec<_>>()
            );
            error!(
                surface = %surface_name,
                config_id = ?surface_config_id,
                default_variant_id = %default_id,
                "❌ {}",
                error_msg
            );
            return Err(anyhow::anyhow!(error_msg));
        }

        info!(
            surface = %surface_name,
            config_id = ?surface_config_id,
            variant_count = channel_surface.variants.len(),
            default_variant_id = ?channel_surface.default_variant_id,
            "Compiling engines for {} surface variant(s)",
            channel_surface.variants.len()
        );

        // Register this channel's route prefix for OpenTelemetry tracing
        crate::observability::register_channel_prefix(surface_route.clone(), format!("[CHANNEL] {}", surface_name));

        // Register task for monitoring if enabled
        if let Some(ref monitor) = task_monitor {
            let now = chrono::Utc::now();
            let channel_task_id = format!(
                "task-{}-{}",
                surface_config_id
                    .as_ref()
                    .unwrap_or(&surface_name),
                uuid::Uuid::new_v4()
            );
            let ap_listen_display = join_host_and_route(&surface_listen_address, &surface_route);
            let task_info = crate::observability::TaskInfo {
                task_id: channel_task_id.clone(),
                config_id: surface_config_id.clone(),
                channel_name: surface_name.clone(),
                transit_point: None,
                listen_address: ap_listen_display,
                target_endpoint: surface_target_endpoint.clone(),
                started_at: now,
                status: crate::observability::TaskStatus::Starting,
                total_connections: 0,
                active_connections: 0,
                bytes_sent: 0,
                bytes_received: 0,
                last_activity: None,
                error_count: 0,
                recent_bytes_sent: 0,
                recent_bytes_received: 0,
                recent_window_start: now,
            };
            monitor
                .register_task(task_info)
                .await;

            // Register one TaskInfo per outbound virtual channel (transit
            // point) so the dashboard renders independent throughput,
            // active-connections, and error rows under the parent surface
            // group. They share `config_id` so cleanup is consolidated.
            if channel_surface
                .transit
                .as_ref()
                .is_some_and(|t| !t.points.is_empty())
            {
                let surface_outbound_listen = channel_surface
                    .transit
                    .as_ref()
                    .and_then(|t| {
                        t.outbound_listen_address
                            .clone()
                    });
                for tp in channel_surface.transit_points() {
                    let tp_task_id = if let Some(cid) = &surface_config_id {
                        format!("task-{}-tp-{}", cid, tp.alias)
                    } else {
                        format!("task-{}-tp-{}-{}", surface_name, tp.alias, uuid::Uuid::new_v4())
                    };
                    let tp_listen = tp
                        .listen_address
                        .clone()
                        .or_else(|| surface_outbound_listen.clone())
                        .unwrap_or_else(|| surface_listen_address.clone());
                    let tp_task = crate::observability::TaskInfo {
                        task_id: tp_task_id,
                        config_id: surface_config_id.clone(),
                        channel_name: surface_name.clone(),
                        transit_point: Some(tp.alias.clone()),
                        listen_address: tp_listen,
                        target_endpoint: tp.target_endpoint.clone(),
                        started_at: now,
                        status: crate::observability::TaskStatus::Running,
                        total_connections: 0,
                        active_connections: 0,
                        bytes_sent: 0,
                        bytes_received: 0,
                        last_activity: None,
                        error_count: 0,
                        recent_bytes_sent: 0,
                        recent_bytes_received: 0,
                        recent_window_start: now,
                    };
                    monitor
                        .register_task(tp_task)
                        .await;
                }
            }

            // Compile identity engines from managed_identity configuration
            let engines = crate::proxy::compile_identity_engines_from_surface(&channel_surface, vc_issuer.as_ref())
                .map_err(|e| {
                    error!(channel = %surface_name, error = %e, "Failed to compile identity engines");
                    anyhow::anyhow!("Failed to compile identity engines for channel {}: {}", surface_name, e)
                })?;
            let identity_rules_engine = engines.rules_engine;
            let identity_selector = engines.selector;
            let protected_rules_engine = engines.protected_rules_engine;
            let protected_selector = engines.protected_selector;
            let external_rules_engine = engines.external_rules_engine;
            let external_selector = engines.external_selector;
            if identity_rules_engine.is_some() {
                info!(channel = %surface_name, "Compiled identity rules engine from managed_identity");
            }
            if identity_selector.is_some() {
                info!(channel = %surface_name, "Compiled identity selector from managed_identity JSON Schema");
            }
            if external_selector.is_some() {
                info!(channel = %surface_name, "Compiled external identity selector from identity_slots.external");
            }

            // Compile engines for each enabled surface variant
            let mut variant_engines = std::collections::HashMap::new();

            for variant in &channel_surface.variants {
                // Skip disabled variants
                if !variant.enabled {
                    info!(
                        surface = %surface_name,
                        variant_id = %variant.id,
                        "Skipping disabled surface variant"
                    );
                    continue;
                }

                // Build the resolved per-variant surface directly
                let variant_surface = match channel_surface.resolve_variant(Some(&variant.alias)) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(channel = %surface_name, variant_id = %variant.id, error = %e, "Failed to resolve variant");
                        return Err(anyhow::anyhow!(
                            "Failed to resolve variant '{}' for channel {}: {}",
                            variant.id,
                            surface_name,
                            e
                        ));
                    }
                };

                // Compile identity engines for this variant
                let variant_engines_compiled = crate::proxy::compile_identity_engines_from_surface(&variant_surface, vc_issuer.as_ref())
                    .map_err(|e| {
                        error!(channel = %surface_name, variant_id = %variant.id, error = %e, "Failed to compile identity engines for variant");
                        anyhow::anyhow!("Failed to compile identity engines for channel {} variant {}: {}", surface_name, variant.id, e)
                    })?;
                if variant_engines_compiled
                    .rules_engine
                    .is_some()
                {
                    info!(channel = %surface_name, variant_id = %variant.id, "Compiled identity rules engine for variant");
                }
                if variant_engines_compiled
                    .selector
                    .is_some()
                {
                    info!(channel = %surface_name, variant_id = %variant.id, "Compiled identity selector for variant");
                }

                // Store compiled engines for this variant
                variant_engines.insert(
                    variant.id.clone(),
                    crate::state::proxy::VariantEngines {
                        identity_rules_engine: variant_engines_compiled.rules_engine,
                        identity_selector: variant_engines_compiled.selector,
                        protected_rules_engine: variant_engines_compiled.protected_rules_engine,
                        protected_selector: variant_engines_compiled.protected_selector,
                        external_rules_engine: variant_engines_compiled.external_rules_engine,
                        external_selector: variant_engines_compiled.external_selector,
                    },
                );
            }

            channel_infos.push(SurfaceInfo {
                surface: Arc::new(channel_surface),
                identity_rules_engine,
                identity_selector,
                protected_rules_engine,
                protected_selector,
                external_rules_engine,
                external_selector,
                variant_engines,
                task_id: channel_task_id,
            });
        }
    }

    let channel_infos_arc = Arc::new(RwLock::new(channel_infos));

    let state = Arc::new(MultiSurfaceProxyState {
        config: Arc::clone(&config),
        network_config: Arc::clone(&network_config),
        client: client.clone(),
        channels: channel_infos_arc.clone(),
        metrics_store: metrics_store.clone(),
        task_monitor: task_monitor.clone(),
        ws_state,
        listener_manager: listener_manager.clone(),
        secrets_store: secrets_store.clone(),
        certificates_store: crate::proxy::server::get_certificates_store(),
        vc_issuer: vc_issuer.clone(),
        policy_manager: policy_manager.clone(),
        gateway_policy_manager: gateway_policy_manager.clone(),
        didauth_session_store: Arc::clone(&didauth_session_store),
        trust_registry_listener_manager:
            crate::gateways::connection_points::message_processor::get_trust_registry_listener_manager(),
        source_auth_middleware: source_auth_middleware.clone(),

        #[cfg(feature = "didwebvh")]
        didwebvh_identity_store: didwebvh_identity_store.clone(),

        #[cfg(feature = "didwebvh")]
        didwebvh_log_manager: didwebvh_log_storage
            .as_ref()
            .map(|s| Arc::new(crate::identity::didwebvh::log::DidLogManager::new(s.clone()))),

        credential_provider_store: crate::proxy::server::get_credential_provider_store(),
        delegation_vault_store: crate::proxy::server::get_delegation_vault_store(),
        egress_allowlist: crate::egress::bdd_egress_allowlist(),
        gateway_base_url: crate::proxy::server::get_gateway_base_url(),
        transit_token_issuer: crate::proxy::server::get_transit_token_issuer(),
        mcp_proxy_store: mcp_proxy_store.clone(),
        a2a_proxy_store: a2a_proxy_store.clone(),
        resolved_surface_cache: resolved_surface_cache.clone(),
    });

    // Settlement worker is spawned in orchestrator.rs - no duplicate needed here

    // Build the Axum router from network configuration
    let mut app = Router::new();

    if let Some(profile) = network_config
        .sts
        .mcp_issuer
        .as_ref()
    {
        profile.validate_network(&network_config)?;
        app = app.merge(profile.discovery_router()?);
    }
    match crate::protocols::protected_resource::metadata_path_owner(&network_config) {
        Some(prefix) => warn!(
            prefix,
            "A configured prefix serves /.well-known/oauth-protected-resource; this listener publishes no protected resource metadata"
        ),
        None => {
            app = app.merge(
                Router::new()
                    .route(
                        "/.well-known/oauth-protected-resource",
                        axum::routing::any(crate::protocols::protected_resource::protected_resource_metadata),
                    )
                    .route(
                        "/.well-known/oauth-protected-resource/{*path}",
                        axum::routing::any(crate::protocols::protected_resource::protected_resource_metadata),
                    )
                    .layer(axum::middleware::map_response(withhold_target_cookies))
                    .layer(if crate::protocols::protected_resource::proxies_metadata_paths(&network_config) {
                        proxy_cors_layer(&network_config.cors)
                    } else {
                        metadata_cors_layer(&network_config.cors)
                    })
                    .with_state(state.as_ref().clone()),
            );
        }
    }

    // A channel, MCP proxy, proxy or redirect prefix that would hide a dashboard
    // page is not registered; startup and reload log each one it skips.
    let hides_dashboard_page = |prefix: &str| crate::proxy::paths::shadowed_dashboard_page(prefix).is_some();

    // Merge DID router first (at root level) to ensure did:web routes are accessible
    if let Some(ref did_router_ref) = did_router {
        info!("Merging DID resolution router at root level");
        app = app.merge(did_router_ref.clone());
    }

    // Note: Secrets/Vault router will be merged AFTER regular routes to take precedence

    // x402 Admin API is mounted inside the identity router (built in orchestrator)
    // so it inherits the global `require_session_auth` layer. All /api/* data
    // calls go through the same protected pipeline — no special cases.

    // Separate fallback routes from regular routes
    let mut fallback_routes = Vec::new();
    let mut regular_routes = Vec::new();

    for (route_name, route_config) in &network_config.routes {
        if matches!(route_config.route_type, crate::config::RouteType::Proxy | crate::config::RouteType::Redirect)
            && hides_dashboard_page(&route_config.prefix)
        {
            continue;
        }
        if route_config.route_type == crate::config::RouteType::Static && route_config.fallback {
            fallback_routes.push((route_name, route_config));
        } else {
            regular_routes.push((route_name, route_config));
        }
    }

    // Process regular routes first
    for (route_name, route_config) in regular_routes {
        match route_config.route_type {
            crate::config::RouteType::IdentityApi => {
                if let Some(ref identity_router) = identity_api_router {
                    info!("Adding Identity API routes at prefix: {}", route_config.prefix);
                    if route_config.prefix == "/" {
                        // Merge at root
                        app = app.merge(identity_router.clone());
                    } else {
                        // Nest under prefix
                        app = app.nest(&route_config.prefix, identity_router.clone());
                    }
                } else {
                    info!("Skipping Identity API route '{}': router not provided", route_name);
                }
            }
            crate::config::RouteType::Onboarding => {
                if let Some(ref onboarding_router_ref) = onboarding_router {
                    info!("Adding Onboarding routes at prefix: {}", route_config.prefix);
                    if route_config.prefix == "/" {
                        // Merge at root
                        app = app.merge(onboarding_router_ref.clone());
                    } else {
                        // Nest under prefix
                        app = app.nest(&route_config.prefix, onboarding_router_ref.clone());
                    }
                } else {
                    info!("Skipping Onboarding route '{}': router not provided", route_name);
                }
            }
            crate::config::RouteType::ConnectionPoint => {
                info!("Adding connection point DID routes '{}' at prefix: {}", route_name, route_config.prefix);

                // Create a connection point store
                let cp_store = std::sync::Arc::new(
                    crate::gateways::FileSystemConnectionPointStore::new(std::path::PathBuf::from(
                        &bootstrap_config
                            .storage_paths
                            .connection_points,
                    ))
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to create connection point store: {}", e))?,
                );

                // Create a router for connection point DID documents only (no state needed)
                let cp_router = Router::new()
                    .route(
                        "/{cp_id}/did.json",
                        axum::routing::get(
                            crate::gateways::connection_points::handlers::serve_connection_point_did_document::<
                                crate::gateways::FileSystemConnectionPointStore,
                            >,
                        ),
                    )
                    .route(
                        "/{cp_id}/did.jsonl",
                        axum::routing::get(
                            crate::gateways::connection_points::handlers::serve_connection_point_did_jsonl::<
                                crate::gateways::FileSystemConnectionPointStore,
                            >,
                        ),
                    )
                    .route(
                        "/{cp_id}/did-witness.json",
                        axum::routing::get(
                            crate::gateways::connection_points::handlers::serve_connection_point_did_witness::<
                                crate::gateways::FileSystemConnectionPointStore,
                            >,
                        ),
                    )
                    .layer(axum::Extension(bootstrap_config.clone()))
                    .layer(axum::Extension(cp_store));

                app = app.merge(
                    Router::new()
                        .nest(&route_config.prefix, cp_router)
                        .with_state(state.as_ref().clone()),
                );
            }
            crate::config::RouteType::Redirect => {
                if let Some(ref target) = route_config.target {
                    info!("Adding redirect route '{}': {} -> {}", route_name, route_config.prefix, target);

                    let target_url = target.clone();
                    let redirect_handler = move || async move { axum::response::Redirect::permanent(&target_url) };

                    app = app.route(&route_config.prefix, axum::routing::get(redirect_handler));
                } else {
                    warn!("Redirect route '{}' missing 'target' field", route_name);
                }
            }
            crate::config::RouteType::Static => {
                if let Some(ref static_path) = route_config.path {
                    let resolved = std::fs::canonicalize(static_path)
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|e| format!("<unresolved: {}>", e));
                    let cwd = std::env::current_dir()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| "?".to_string());
                    info!(
                        "[WWW Hosting on port {}] static file server '{}' at prefix: {} (path: {} | cwd: {} | resolved: {})",
                        port, route_name, route_config.prefix, static_path, cwd, resolved
                    );

                    let serve_dir = static_site(static_path);

                    if route_config.prefix == "/" {
                        app = app.nest_service("/", serve_dir);
                    } else {
                        app = app.nest_service(&route_config.prefix, serve_dir);
                    }
                } else {
                    warn!("Static route '{}' missing 'path' field", route_name);
                }
            }
            crate::config::RouteType::Proxy => {
                info!("Adding proxy route '{}' at prefix: {}", route_name, route_config.prefix);

                // Register this prefix for OpenTelemetry tracing
                crate::observability::register_channel_prefix(
                    route_config.prefix.clone(),
                    format!("[CHANNEL] {}", route_name),
                );

                // Add route for this proxy path
                let prefix = route_config.prefix.clone();
                let proxy_router = Router::new()
                    .route(
                        &format!("{}/{{{}}}", prefix, "*path"),
                        axum::routing::any(super::handler::multi_channel_proxy_handler),
                    )
                    .layer(axum::middleware::map_response(withhold_target_cookies))
                    .layer(proxy_cors_layer(&network_config.cors))
                    .with_state(state.as_ref().clone());

                app = app.merge(proxy_router);
            }
        }
    }

    // Add proxy routes for each channel prefix
    for channel_prefix in network_config
        .channels
        .iter()
        .filter(|channel| !hides_dashboard_page(&channel.prefix))
    {
        info!("Adding channel proxy route '{}' at prefix: {}", channel_prefix.name, channel_prefix.prefix);

        // Register this prefix for OpenTelemetry tracing
        crate::observability::register_channel_prefix(
            channel_prefix.prefix.clone(),
            format!("[CHANNEL] {}", channel_prefix.name),
        );

        let prefix = channel_prefix.prefix.clone();
        let mut proxy_router = Router::new()
            .route(
                &format!("{}/{{{}}}", prefix, "*path"),
                axum::routing::any(super::handler::multi_channel_proxy_handler),
            )
            .route(&prefix, axum::routing::any(super::handler::multi_channel_proxy_handler));

        // Surface variant URL grammar (plan §2.3): also accept `{prefix}$<alias>`
        // and `{prefix}$<alias>/{rest}` for every variant alias on every channel
        // bound to this prefix. axum's matchit can't match a `$alias` mid-segment,
        // so we register one route per known alias instead.
        let mut registered_alias_routes: std::collections::HashSet<String> = std::collections::HashSet::new();
        for surface in &surfaces {
            if surface.access_point.route != prefix {
                continue;
            }
            for vc in &surface.variants {
                // Register both the literal `$alias` and the percent-encoded
                // `%24alias` form (plan §2.3 — `%24` MUST be tolerated).
                for sigil in ["$", "%24"] {
                    let alias_route = format!("{}{}{}", prefix, sigil, vc.alias);
                    if registered_alias_routes.insert(alias_route.clone()) {
                        proxy_router = proxy_router
                            .route(&alias_route, axum::routing::any(super::handler::multi_channel_proxy_handler))
                            .route(
                                &format!("{}/{{{}}}", alias_route, "*path"),
                                axum::routing::any(super::handler::multi_channel_proxy_handler),
                            );
                    }
                }
            }
        }

        let proxy_router = proxy_router
            .layer(axum::middleware::map_response(withhold_target_cookies))
            .layer(axum::middleware::from_fn(crate::observability::trace_http_request))
            .layer(surface_cors_layer(&network_config.cors, &state.channels))
            .with_state(state.as_ref().clone());

        app = app.merge(proxy_router);
    }

    // Add MCP proxy routes for each configured MCP proxy path
    let mcp_proxy_paths = network_config
        .mcp_proxies
        .as_ref();

    if let Some(mcp_proxies) = mcp_proxy_paths {
        // Shared SSE session manager for all MCP proxy routes
        let sse_session_mgr = crate::mcp::sse_server::SseSessionManager::new(None);

        for mcp_proxy_prefix in mcp_proxies
            .iter()
            .filter(|proxy| !hides_dashboard_page(&proxy.prefix))
        {
            info!("Adding MCP proxy route '{}' at prefix: {}", mcp_proxy_prefix.name, mcp_proxy_prefix.prefix);

            // Register this prefix for OpenTelemetry tracing
            crate::observability::register_mcp_prefix(
                mcp_proxy_prefix
                    .prefix
                    .clone(),
                format!("[MCP] {}", mcp_proxy_prefix.name),
            );

            if let (Some(store), Some(manager)) = (mcp_proxy_store.as_ref(), mcp_server_manager.as_ref()) {
                let prefix = mcp_proxy_prefix
                    .prefix
                    .clone();
                let route_path = format!("{}/{{{}}}", prefix, "*path");
                let mut mcp_router =
                    Router::new()
                        .route(
                            &route_path,
                            axum::routing::get(
                                crate::mcp_proxies::handlers::handle_mcp_get::<
                                    crate::mcp_proxies::FileSystemMcpProxyStore,
                                >,
                            )
                            .delete(
                                crate::mcp_proxies::handlers::handle_mcp_get::<
                                    crate::mcp_proxies::FileSystemMcpProxyStore,
                                >,
                            ),
                        )
                        .route(
                            &route_path,
                            axum::routing::post(
                                crate::mcp_proxies::handlers::handle_mcp_post::<
                                    crate::mcp_proxies::FileSystemMcpProxyStore,
                                >,
                            ),
                        )
                        .layer(axum::Extension(store.clone()))
                        .layer(axum::Extension(manager.clone()))
                        .layer(axum::Extension(network_config.clone()))
                        .layer(axum::Extension(sse_session_mgr.clone()));

                if let Some(issuer) = vc_issuer.as_ref() {
                    mcp_router =
                        mcp_router.layer(axum::Extension(crate::mcp::resource_server::ResourceServerAuthContext {
                            issuer: issuer.clone(),
                            keys: Arc::new(crate::jwt_bearer::JwksClient::new()),
                            sts_token_origins: source_auth_middleware
                                .as_ref()
                                .and_then(|middleware| middleware.sts_token_origins()),
                        }));
                }
                app = app.merge(mcp_router);
            } else {
                warn!("MCP proxy route '{}' skipped: store or manager not initialized", mcp_proxy_prefix.name);
            }
        }
    }

    if config
        .facilitator_mode
        .enable_test_endpoints
    {
        warn!("facilitator_mode.enable_test_endpoints is ignored: the x402 test endpoints are no longer served");
    }

    // Proxy {TP_OUTBOUND_PATH_PREFIX}/* to the outbound listener when inbound and outbound share a hostname.
    //
    // On a shared-domain deployment the reverse-proxy routes all traffic to the inbound port
    // regardless of path. Requests that start with {TP_OUTBOUND_PATH_PREFIX} are destined for a transit
    // point — they need to reach the outbound listener. Rather than registering per-TP routes
    // at startup (which require a restart every time a TP is added), register a single wildcard
    // proxy that forwards any {TP_OUTBOUND_PATH_PREFIX}/* request to localhost:{outbound_port}. The outbound
    // listener already has all the specific TP routes and handles them correctly.
    //
    // The proxy is only registered when at least one outbound listener shares a hostname with
    // this inbound port's external URLs (detected by hostname intersection).
    {
        if let Some(outbound_listener) = find_shared_outbound_listener(&network_config, port) {
            let outbound_target =
                format!("http://{}", listener_socket_address(&outbound_listener.bind_address, outbound_listener.port)?);
            info!(
                inbound_port = port,
                outbound_port = outbound_listener.port,
                outbound_target = %outbound_target,
                "Shared-domain detected: registering outbound transit-point proxy on inbound listener -> outbound listener"
            );

            let hop = Arc::new(SharedHostHop {
                target: outbound_target,
                client: crate::http_client::shared_host_hop(SHARED_HOST_HOP_READ_IDLE)?,
                forwarded_cert_header: config
                    .tls
                    .client_auth
                    .forwarded_header
                    .header_name
                    .clone(),
                max_body_bytes: config.a2a.max_body_size,
            });
            let proxy_handler = move |req: axum::extract::Request| forward_shared_host_hop(hop.clone(), req);

            let outbound_prefix = crate::proxy::outbound_handler::TP_OUTBOUND_PATH_PREFIX;
            app = app
                .route(outbound_prefix, axum::routing::any(proxy_handler.clone()))
                .route(&format!("{}/{{*path}}", outbound_prefix), axum::routing::any(proxy_handler));
        }
    }

    // Merge Secrets/Vault router AFTER all regular routes (to override any wildcards/fallbacks in nested routers)
    // This ensures /api/v1/secrets/ and /api/v1/apikeys/ take precedence over identity router's fallback
    if let Some(ref secrets_router_ref) = secrets_router {
        info!("Merging Secrets/Vault API router (after regular routes, before fallbacks)");
        app = app.merge(secrets_router_ref.clone());
    }

    if config
        .facilitator_mode
        .facilitator_via_http
    {
        warn!("facilitator_mode.facilitator_via_http is ignored: the /api/x402 facilitator is no longer served");
    }

    // Process fallback routes last so they don't override specific routes
    let api_prefixes = if identity_api_router.is_some() {
        identity_api_prefixes(&network_config)
    } else {
        Vec::new()
    };
    for (route_name, route_config) in fallback_routes {
        if let Some(ref static_path) = route_config.path {
            let resolved = std::fs::canonicalize(static_path)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|e| format!("<unresolved: {}>", e));
            let cwd = std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "?".to_string());
            info!(
                "[WWW Hosting on port {}] static file server '{}' at prefix: {} (path: {} | cwd: {} | resolved: {})",
                port, route_name, route_config.prefix, static_path, cwd, resolved
            );

            app = app.fallback_service(dashboard_fallback(static_path, api_prefixes.clone()));
        }
    }

    // The consent binding cookie is never forwarded and never set by an upstream.
    let app = app.layer(axum::middleware::from_fn(crate::delegation_vault::consent_cookie::guard));

    // Add OpenTelemetry tracing middleware for all proxy requests
    let app = app.layer(axum::middleware::from_fn(crate::observability::trace_http_request));

    // Unconditional access log: every inbound request, regardless of routing.
    let app = app.layer(axum::middleware::from_fn(crate::observability::access_log));

    // Forwarded client-cert capture (XFCC etc.) — no-op when
    // `client_auth.trusted_proxies` is empty.
    let app = app.layer(axum::middleware::from_fn_with_state(
        std::sync::Arc::new(config.tls.client_auth.clone()),
        crate::source_auth::peer_cert::forwarded_peer_cert,
    ));

    // Caller IP for per-client limits; forwarded headers count only from `client_ip.trusted_proxies`.
    let app = app.layer(axum::middleware::from_fn_with_state(
        std::sync::Arc::new(
            network_config
                .client_ip
                .clone(),
        ),
        crate::source_auth::client_ip::resolve_client_ip_layer,
    ));

    // Promote a direct-TLS peer cert (captured by PeerCertAcceptor when
    // `client_auth.direct` is enabled) into the canonical PeerCertInfo
    // extension. No-op when the upstream extension is absent.
    let app = app.layer(axum::middleware::from_fn(crate::source_auth::peer_cert::promote_direct_peer_cert));

    info!("Port listener router on port {} serves {} channels", port, surfaces.len());
    for surface in &surfaces {
        info!(
            "  Channel '{}' route '{}' -> {}",
            surface.name,
            surface.route(),
            loggable::url(surface.target_endpoint())
        );
    }

    // Update status to running for all channels
    if let Some(ref monitor) = task_monitor {
        let channel_infos = channel_infos_arc.read().await;
        for channel_info in channel_infos.iter() {
            monitor
                .update_status(&channel_info.task_id, crate::observability::TaskStatus::Running)
                .await;
        }
    }

    Ok((app, state))
}

/// Get the shared outbound channel state for `config_id`.
///
/// Existing listeners keep a clone of this shared state, so reloads must update
/// the state itself. If we replace the `Arc`, those listeners keep using the old
/// transit-point target or identity engines until restart. Route shape changes
/// such as `listen_path` are baked into Axum and require rebuilding the outbound
/// listener routes.
fn get_or_create_outbound_channel_state(
    states: &mut std::collections::HashMap<String, Arc<std::sync::RwLock<crate::state::OutboundSurfaceState>>>,
    config_id: &str,
    outbound_surface: &crate::config::agent_surface::AgentSurface,
    identity_rules_engine: Option<Arc<crate::proxy::RulesEngine>>,
    identity_selector: Option<Arc<crate::identity::IdentitySelector>>,
) -> Arc<std::sync::RwLock<crate::state::OutboundSurfaceState>> {
    if let Some(existing) = states.get(config_id) {
        let mut existing_state = existing
            .write()
            .expect("outbound channel_state lock poisoned");
        existing_state.surface = Arc::new(outbound_surface.clone());
        existing_state.identity_rules_engine = identity_rules_engine;
        existing_state.identity_selector = identity_selector;
        drop(existing_state);
        existing.clone()
    } else {
        let new_state = Arc::new(std::sync::RwLock::new(crate::state::OutboundSurfaceState {
            surface: Arc::new(outbound_surface.clone()),
            identity_rules_engine,
            identity_selector,
        }));
        states.insert(config_id.to_string(), new_state.clone());
        new_state
    }
}

/// The socket address a listener binds on `port`, from its `bind_address`, an
/// IPv4 or IPv6 address, the IPv6 one optionally in brackets.
pub(crate) fn listener_socket_address(
    bind_address: &str,
    port: u16,
) -> anyhow::Result<SocketAddr> {
    let ip = crate::config::network::parse_bind_address(bind_address).map_err(|error| {
        anyhow::anyhow!("Invalid bind_address '{bind_address}' for the listener on port {port}: {error}")
    })?;
    Ok(SocketAddr::new(ip, port))
}

/// The addresses the inbound listener on `port` binds: the distinct
/// `bind_address` of every inbound listener configured for the port, the
/// unspecified ones first (`::` before `0.0.0.0`). A port without an inbound
/// listener is an error rather than a bind on every interface.
pub(crate) fn inbound_bind_addresses(
    network_config: &crate::config::NetworkConfig,
    port: u16,
) -> anyhow::Result<Vec<SocketAddr>> {
    let mut addresses = Vec::new();
    for listener in network_config
        .listeners
        .iter()
        .filter(|listener| listener.listener_type == "inbound" && listener.port == port)
    {
        let address = listener_socket_address(&listener.bind_address, port)?;
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        anyhow::bail!("No inbound listener is configured for port {port}");
    }
    addresses.sort_by_key(|address| (!address.ip().is_unspecified(), address.is_ipv4()));
    Ok(addresses)
}

/// Whether a listener bound on `bound` already accepts connections to
/// `target`: `bound` is the unspecified address of the target's family, or the
/// IPv6 unspecified address of a dual-stack socket (`only_v6` false) and the
/// target is IPv4.
fn bound_address_covers(
    bound: SocketAddr,
    bound_only_v6: bool,
    target: SocketAddr,
) -> bool {
    bound.port() == target.port()
        && bound.ip().is_unspecified()
        && (bound.is_ipv4() == target.is_ipv4() || (bound.is_ipv6() && target.is_ipv4() && !bound_only_v6))
}

/// Whether a bound listener already accepts connections to `target`. A socket
/// whose IPv6-only setting cannot be read is treated as IPv6-only.
fn bound_listener_covers(
    bound: &tokio::net::TcpListener,
    target: SocketAddr,
) -> bool {
    let Ok(address) = bound.local_addr() else {
        return false;
    };
    let only_v6 = address.is_ipv4()
        || socket2::SockRef::from(bound)
            .only_v6()
            .unwrap_or(true);
    bound_address_covers(address, only_v6, target)
}

/// Bind every inbound address of a port. An address the operating system
/// reports in use while a listener already bound on the port accepts its
/// connections, as an IPv6 dual-stack wildcard does for IPv4, is skipped.
pub(crate) async fn bind_inbound_listeners(addresses: &[SocketAddr]) -> anyhow::Result<Vec<tokio::net::TcpListener>> {
    let mut listeners: Vec<tokio::net::TcpListener> = Vec::new();
    for &address in addresses {
        match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => listeners.push(listener),
            Err(error)
                if error.kind() == std::io::ErrorKind::AddrInUse
                    && listeners
                        .iter()
                        .any(|bound| bound_listener_covers(bound, address)) =>
            {
                info!(%address, "Inbound address is already served by the unspecified address bound on its port");
            }
            Err(error) => anyhow::bail!("Failed to bind inbound listener {address}: {error}"),
        }
    }
    Ok(listeners)
}

/// Take a surface's shared outbound state out of service in place. Every route
/// still holding it, on a listener being rebuilt or a connection kept alive
/// past the rebuild, then refuses each request as for a surface without
/// Transit Points, until the surface's Transit Points, if it regains them, are
/// written back into the same state.
pub(crate) fn retire_outbound_channel_state(retired: &std::sync::RwLock<crate::state::OutboundSurfaceState>) {
    let mut state = retired
        .write()
        .expect("outbound channel_state lock poisoned");
    let mut surface = (*state.surface).clone();
    surface.transit = None;
    surface.variants.clear();
    state.surface = Arc::new(surface);
    state.identity_rules_engine = None;
    state.identity_selector = None;
}

/// Build the router of an outbound-only port listener.
///
/// This is the server-side counterpart of the outbound pipeline.  Unlike
/// [`build_port_router`] (which builds a complex multi-channel inbound router)
/// this function is intentionally minimal:
/// - One route per `(channel, virtual_channel)` pair.
/// - No identity API, no MCP proxies, no payment routes.
/// - Each route carries a dedicated [`OutboundProxyState`].
///
/// The caller is responsible for only passing channels that have `outbound.enabled = true`.
///
/// Every surface's state is in `outbound_channel_states` when this returns, so
/// a later surface removal always finds the state it must retire. Binding the
/// port is left to the caller, so a rebuilt router can replace the one a bound
/// listener serves.
pub async fn build_outbound_port_router(
    port: u16,
    channels: Vec<(crate::config::agent_surface::AgentSurface, Vec<crate::config::agent_surface::TransitPoint>)>,
    config: Arc<crate::config::GatewayConfig>,
    network_config: Arc<crate::config::NetworkConfig>,
    metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
    secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
    policy_manager: Option<Arc<crate::policies::SurfacePolicyManager>>,
    gateway_policy_manager: Option<Arc<crate::policies::GatewayPolicyManager>>,
    trust_registry_listener_manager: Option<Arc<crate::trust_registries::TrustRegistryListenerManager>>,
    vc_issuer: Option<Arc<crate::identity::VCIssuer>>,
    task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    outbound_channel_states: Arc<
        std::sync::RwLock<
            std::collections::HashMap<String, Arc<std::sync::RwLock<crate::state::OutboundSurfaceState>>>,
        >,
    >,
    listener_manager: Arc<tokio::sync::RwLock<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>>,
    source_auth_middleware: Option<Arc<crate::source_auth::SourceAuthMiddleware>>,
) -> anyhow::Result<Router> {
    use axum::routing::any;

    info!("Building the outbound port listener router on port {} for {} channel(s)", port, channels.len());

    // Liveness probe for the channel/outbound listener (e.g. port 5000). This
    // listener has no identity router, so `/alive` is registered directly here
    // for ECS/ALB target-group health checks. Always 200 while the process is up.
    let mut app = Router::new().route("/alive", axum::routing::get(crate::identity::handlers::alive_check));
    let mut metadata_surfaces = Vec::new();

    // Every route path registered on this listener. Save-time validation
    // rejects colliding `listen_path`s, but config edited on disk (or missed
    // by older validation) can still contain duplicates — registering one
    // twice makes `Router::route`/`merge` panic and kills the whole
    // listener rebuild. Duplicates are skipped with an error instead: the
    // first registrant keeps the route.
    let mut registered_routes: std::collections::HashSet<String> =
        std::collections::HashSet::from(["/alive".to_string()]);

    for (surface, tps_for_this_port) in &channels {
        let Some(ref transit) = surface.transit else {
            continue;
        };
        if transit.points.is_empty() {
            continue;
        }

        // Resolve default-variant overrides (base mode) so any
        // managed_identity / trust_registry_injection promoted at the
        // surface level still applies to outbound traffic.
        let outbound_surface = surface
            .resolve_variant(None)
            .unwrap_or_else(|_| surface.clone());
        let mut warnings = outbound_surface.validate_outbound();
        for warning in surface.validate_outbound() {
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
        }
        for e in warnings {
            tracing::warn!(channel = %outbound_surface.name, "Outbound validation warning: {}", e);
        }
        for open in open_transit_points(&network_config, surface)
            .into_iter()
            .filter(|open| open.port == Some(port))
        {
            match open.exposure() {
                Some(exposure) => tracing::warn!(channel = %outbound_surface.name, "{exposure}"),
                None => tracing::warn!(
                    channel = %outbound_surface.name,
                    transit_point = %open.alias,
                    variant = ?open.variant,
                    "Transit Point serves callers it does not authenticate"
                ),
            }
        }
        let route_prefix = outbound_surface
            .route()
            .trim_end_matches('/');

        // Compile identity engines (lenient — log errors but don't fail startup).
        let outbound_engines = crate::proxy::compile_identity_engines_from_surface(&outbound_surface, vc_issuer.as_ref())
            .map_err(|e| {
                tracing::error!(channel = %outbound_surface.name, error = %e, "Failed to compile outbound identity engines");
                e
            })
            .unwrap_or(crate::proxy::CompiledIdentityEngines {
                rules_engine: None,
                selector: None,
                protected_rules_engine: None,
                protected_selector: None,
                external_rules_engine: None,
                external_selector: None,
            });
        let identity_rules_engine = outbound_engines.rules_engine;
        let identity_selector = outbound_engines.selector;

        // Create or reuse shared channel state. A channel whose VCs span
        // multiple outbound ports must reference the *same* state across
        // all ports so hot-reload (which keys updates by config_id)
        // propagates rule-engine changes everywhere. Without this dedupe,
        // the second port to start would clobber the first port's entry
        // in `outbound_channel_states` and orphan its handlers.
        let channel_state = if let Some(config_id) = outbound_surface.config_id() {
            let config_id = config_id.to_string();
            let mut states = outbound_channel_states
                .write()
                .expect("outbound_channel_states lock poisoned");
            get_or_create_outbound_channel_state(
                &mut states,
                &config_id,
                surface,
                identity_rules_engine,
                identity_selector,
            )
        } else {
            Arc::new(std::sync::RwLock::new(crate::state::OutboundSurfaceState {
                surface: Arc::new(surface.clone()),
                identity_rules_engine,
                identity_selector,
            }))
        };

        metadata_surfaces.push(channel_state.clone());
        for vc in tps_for_this_port {
            let state = crate::state::OutboundProxyState {
                network_config: network_config.clone(),
                channel_state: channel_state.clone(),
                metrics_store: metrics_store.clone(),
                secrets_store: secrets_store.clone(),
                certificates_store: crate::proxy::server::get_certificates_store(),
                policy_manager: policy_manager.clone(),
                gateway_policy_manager: gateway_policy_manager.clone(),
                trust_registry_listener_manager: trust_registry_listener_manager.clone(),
                listener_manager: listener_manager.clone(),
                vc_issuer: vc_issuer.clone(),
                transit_token_issuer: get_transit_token_issuer(),
                delegation_vault_store: get_delegation_vault_store(),
                credential_provider_store: get_credential_provider_store(),
                mcp_proxy_store: crate::gateways::get_mcp_proxy_store(),
                consent_identity_strategies: source_auth_middleware
                    .as_ref()
                    .map(|middleware| middleware.provider_store()),
                source_auth_middleware: source_auth_middleware.clone(),
                mcp_continuations: crate::mcp::continuations::config::global().map(|runtime| Arc::new(runtime.clone())),
                gateway_base_url: get_gateway_base_url(),
                task_monitor: task_monitor.clone(),
                max_response_bytes: config.a2a.max_body_size,
                max_request_bytes: config.a2a.max_body_size,
                egress_allowlist: crate::egress::bdd_egress_allowlist(),
                vc_alias_override: vc
                    .listen_path
                    .as_ref()
                    .map(|_| vc.alias.clone()),
            };

            // Route registration:
            //   * Always register `{TP_OUTBOUND_PATH_PREFIX}/<channel-route>/<alias>` so the
            //     `{TP_OUTBOUND_PATH_PREFIX}` prefix is a consistent convention on every
            //     outbound listener regardless of `listen_path`.
            //   * When `vc.listen_path` is also set, additionally register
            //     that custom path (the handler uses `vc_alias_override` to
            //     resolve the VC without parsing the request path).
            let outbound_prefix = crate::proxy::outbound_handler::TP_OUTBOUND_PATH_PREFIX;
            let (outbound_base, outbound_wildcard) = if route_prefix.is_empty() || route_prefix == "/" {
                (format!("{}/{}", outbound_prefix, vc.alias), format!("{}/{}/{{*path}}", outbound_prefix, vc.alias))
            } else {
                (
                    format!("{}{}/{}", outbound_prefix, route_prefix, vc.alias),
                    format!("{}{}/{}/{{*path}}", outbound_prefix, route_prefix, vc.alias),
                )
            };

            info!(
                surface = %outbound_surface.name,
                alias = %vc.alias,
                target = %loggable::url(&vc.target_endpoint),
                route = %outbound_wildcard,
                listen_path = ?vc.listen_path,
                "Registering outbound virtual channel route"
            );

            let mut vc_routes = vec![outbound_base, outbound_wildcard];

            if let Some(ref custom) = vc.listen_path {
                let trimmed = custom
                    .trim_end_matches('/')
                    .to_string();
                let trimmed = if trimmed.is_empty() {
                    "/".to_string()
                } else {
                    trimmed
                };
                let listen_wildcard = format!("{}/{{*path}}", trimmed);
                info!(
                    surface = %outbound_surface.name,
                    alias = %vc.alias,
                    route = %listen_wildcard,
                    "Registering outbound virtual channel listen_path route"
                );
                vc_routes.push(trimmed);
                vc_routes.push(listen_wildcard);
            }

            for variant in &surface.variants {
                for separator in ["$", "%24"] {
                    let variant_route =
                        format!("{outbound_prefix}{route_prefix}{separator}{}/{}", variant.alias, vc.alias);
                    vc_routes.push(format!("{variant_route}/{{*path}}"));
                    vc_routes.push(variant_route);
                    if let Some(custom) = vc.listen_path.as_deref() {
                        let custom = custom.trim_end_matches('/');
                        let variant_route = format!("{custom}{separator}{}", variant.alias);
                        vc_routes.push(format!("{variant_route}/{{*path}}"));
                        vc_routes.push(variant_route);
                    }
                }
            }

            // Register each route only once — a duplicate would panic axum's
            // router and take the listener (re)build down with it.
            for route in vc_routes {
                if !registered_routes.insert(route.clone()) {
                    tracing::error!(
                        surface = %outbound_surface.name,
                        alias = %vc.alias,
                        route = %route,
                        port,
                        "Duplicate outbound route on this listener — skipping; traffic on this route is served by the surface that registered it first"
                    );
                    continue;
                }
                app = app.route(&route, any(super::outbound_handler::outbound_proxy_handler).with_state(state.clone()));
            }
        }
    }
    if network_config
        .sts
        .mcp_issuer
        .is_some()
    {
        let metadata_state = crate::mcp::resource_server::TransitMetadataState {
            network: network_config.clone(),
            surfaces: metadata_surfaces,
            port,
        };
        app = app.merge(
            Router::new()
                .route(
                    "/.well-known/oauth-protected-resource",
                    axum::routing::get(crate::mcp::resource_server::transit_metadata),
                )
                .route(
                    "/.well-known/oauth-protected-resource/{*path}",
                    axum::routing::get(crate::mcp::resource_server::transit_metadata),
                )
                .with_state(metadata_state),
        );
    }

    let app = app.layer(axum::middleware::from_fn(crate::delegation_vault::consent_cookie::guard));
    let app = app.layer(axum::middleware::from_fn(crate::observability::trace_http_request));
    let app = app.layer(axum::middleware::from_fn(crate::observability::access_log));
    let app = app.layer(axum::middleware::from_fn_with_state(
        std::sync::Arc::new(config.tls.client_auth.clone()),
        crate::source_auth::peer_cert::forwarded_peer_cert,
    ));
    Ok(app.layer(axum::middleware::from_fn(crate::source_auth::peer_cert::promote_direct_peer_cert)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use futures::StreamExt;

    async fn dashboard_answer(
        api_prefixes: &[&str],
        path: &str,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        use tower::ServiceExt;
        let www = tempfile::tempdir().expect("tempdir");
        std::fs::write(www.path().join("index.html"), "<html>dashboard</html>").expect("write index.html");
        let response = dashboard_fallback(
            www.path()
                .to_str()
                .expect("utf-8 path"),
            api_prefixes
                .iter()
                .map(|prefix| prefix.to_string())
                .collect(),
        )
        .oneshot(
            axum::http::Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("dashboard fallback answers");
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn an_unmatched_path_under_the_identity_api_is_not_found_not_the_dashboard() {
        for path in ["/api", "/api/", "/api/v1/does-not-exist", "/api/v1/secrets/x/y?z=1"] {
            let (status, headers, body) = dashboard_answer(&["/api"], path).await;

            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            for (header, value) in [
                ("content-type", "application/json"),
                ("cache-control", "no-store"),
                ("x-content-type-options", "nosniff"),
                ("x-frame-options", "DENY"),
                ("content-security-policy", "frame-ancestors 'none'"),
            ] {
                assert_eq!(
                    headers
                        .get(header)
                        .and_then(|value| value.to_str().ok()),
                    Some(value),
                    "{path} {header}"
                );
            }
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&body).expect("json body"),
                serde_json::json!({"error": "Not found"}),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn dashboard_pages_outside_the_identity_api_still_get_the_dashboard() {
        for path in ["/", "/settings/general", "/apiary", "/api-keys/new", "/apikeys", "/surfaces/api"] {
            let (status, _, body) = dashboard_answer(&["/api"], path).await;

            assert_eq!(status, StatusCode::OK, "{path}");
            assert!(body.contains("dashboard"), "{path}: {body}");
        }
    }

    #[tokio::test]
    async fn without_an_identity_api_prefix_every_path_gets_the_dashboard() {
        let (status, _, body) = dashboard_answer(&[], "/api/v1/does-not-exist").await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("dashboard"), "{body}");
    }

    #[test]
    fn identity_api_prefixes_skip_a_root_mount_and_drop_trailing_slashes() {
        let config: crate::config::NetworkConfig = serde_json::from_value(serde_json::json!({
            "did": { "domain": "test.example.com" },
            "webauthn": { "rp_id": "test", "external_origin": "https://test.example.com" },
            "integration": { "types": [], "categories": [] },
            "listeners": [],
            "routes": {
                "api": {"type": "identity_api", "prefix": "/api/"},
                "root": {"type": "identity_api", "prefix": "/"},
                "dashboard": {"type": "static", "prefix": "/", "path": "www", "fallback": true}
            }
        }))
        .expect("network config");

        assert_eq!(identity_api_prefixes(&config), vec!["/api".to_string()]);
    }

    #[test]
    fn parse_cors_origins_keeps_valid_origins() {
        let origins =
            parse_cors_origins(&["https://copilotstudio.microsoft.com".to_string(), "not a header\nvalue".to_string()]);

        assert_eq!(origins.len(), 1);
        assert_eq!(origins[0], HeaderValue::from_static("https://copilotstudio.microsoft.com"));
    }

    #[test]
    fn proxy_cors_allows_any_origin_for_public_discovery_paths() {
        let origin = HeaderValue::from_static("https://copilotstudio.microsoft.com");
        let origins = Vec::new();

        assert!(is_proxy_cors_origin_allowed(
            &origin,
            "GET",
            "/agents/copilot-worker/.well-known/agent-card.json",
            &origins,
        ));
        assert!(is_proxy_cors_origin_allowed(&origin, "HEAD", "/agents/copilot-worker/discovery", &origins,));
    }

    #[tokio::test]
    async fn only_the_metadata_routes_let_any_origin_read_protected_resource_metadata() {
        use axum::http::{Request, StatusCode, header};
        use tower::ServiceExt;
        let request = |method: &str, preflight_for: Option<&str>| {
            let mut request = Request::builder()
                .method(method)
                .uri("/.well-known/oauth-protected-resource/mcp/alpha")
                .header(header::ORIGIN, "https://client.example");
            if let Some(requested) = preflight_for {
                request = request.header(header::ACCESS_CONTROL_REQUEST_METHOD, requested);
            }
            request
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let allowed = |layer: CorsLayer, method: &'static str, preflight_for: Option<&'static str>| async move {
            Router::new()
                .route("/{*path}", axum::routing::any(|| async { StatusCode::OK }))
                .layer(layer)
                .oneshot(request(method, preflight_for))
                .await
                .unwrap()
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        };
        let cors = ["https://dashboard.example.com".to_string()];

        assert!(allowed(metadata_cors_layer(&cors), "GET", None).await);
        let read = Router::new()
            .route("/{*path}", axum::routing::any(|| async { StatusCode::UNAUTHORIZED }))
            .layer(proxy_cors_layer(&["https://client.example".to_string()]))
            .oneshot(request("GET", None))
            .await
            .unwrap();
        assert_eq!(read.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS], "www-authenticate");
        assert!(allowed(metadata_cors_layer(&cors), "HEAD", None).await);
        assert!(allowed(metadata_cors_layer(&cors), "OPTIONS", Some("GET")).await);
        assert!(!allowed(metadata_cors_layer(&cors), "OPTIONS", Some("POST")).await);
        // A channel proxying the same path keeps the allowlist.
        assert!(!allowed(proxy_cors_layer(&cors), "GET", None).await);
    }

    #[test]
    fn only_a_catch_all_at_the_root_or_well_known_proxies_the_metadata_paths() {
        use crate::protocols::protected_resource::proxies_metadata_paths;
        let mut network = crate::protocols::protected_resource::fixtures::discovery_network();
        assert!(!proxies_metadata_paths(&network));
        let channel = |prefix: &str| crate::config::network::ChannelPrefix {
            id: "channel".into(),
            name: "channel".into(),
            prefix: prefix.into(),
        };
        for (prefix, proxies) in [
            ("/.well-known", true),
            ("/", false),
            ("/agents", false),
            ("/.well-known/oauth-protected-resource", false),
            ("/.well-known/oauth-protected-resource/mcp", false),
        ] {
            network.channels = vec![channel(prefix)];
            assert_eq!(proxies_metadata_paths(&network), proxies, "channel {prefix}");
        }
        network.channels = Vec::new();
        for (prefix, proxies) in [("", true), ("/", false)] {
            network.routes = serde_json::from_value(serde_json::json!({
                "root": {"type": "proxy", "prefix": prefix}
            }))
            .unwrap();
            assert_eq!(proxies_metadata_paths(&network), proxies, "proxy route {prefix:?}");
        }
    }

    #[test]
    fn a_prefix_at_the_metadata_path_keeps_it() {
        use crate::protocols::protected_resource::metadata_path_owner;
        let mut network = crate::protocols::protected_resource::fixtures::discovery_network();
        assert_eq!(metadata_path_owner(&network), None);
        for prefix in ["/.well-known", "/.well-known/oauth-protected-resource/mcp", "/agents"] {
            network.channels = vec![crate::config::network::ChannelPrefix {
                id: "channel".into(),
                name: "channel".into(),
                prefix: prefix.into(),
            }];
            assert_eq!(metadata_path_owner(&network), None, "{prefix}");
        }
        for prefix in ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/"] {
            network.channels = vec![crate::config::network::ChannelPrefix {
                id: "channel".into(),
                name: "channel".into(),
                prefix: prefix.into(),
            }];
            assert_eq!(metadata_path_owner(&network), Some(prefix));
        }
    }

    fn browser_origin_surface(
        route: &str,
        origins: &[&str],
    ) -> SurfaceInfo {
        let mut surface = crate::config::agent_surface::AgentSurface {
            name: route
                .trim_start_matches('/')
                .to_string(),
            browser_origins: origins
                .iter()
                .map(|origin| origin.to_string())
                .collect(),
            ..Default::default()
        };
        surface.access_point.route = route.to_string();
        SurfaceInfo {
            surface: Arc::new(surface),
            identity_rules_engine: None,
            identity_selector: None,
            protected_rules_engine: None,
            protected_selector: None,
            external_rules_engine: None,
            external_selector: None,
            task_id: route.to_string(),
            variant_engines: Default::default(),
        }
    }

    async fn browser_origin_response(
        surfaces: &Arc<RwLock<Vec<SurfaceInfo>>>,
        cors: &[&str],
        origin: &str,
        method: &str,
        path: &str,
        preflight_for: Option<&str>,
    ) -> axum::response::Response {
        use axum::http::{Request, header};
        use tower::ServiceExt;
        let cors: Vec<String> = cors
            .iter()
            .map(|origin| origin.to_string())
            .collect();
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::ORIGIN, origin);
        if let Some(requested) = preflight_for {
            request = request
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, requested)
                .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type");
        }
        let event_stream = path.ends_with("/stream");
        Router::new()
            .route(
                "/{*path}",
                axum::routing::any(move || async move {
                    let content_type = if event_stream {
                        "text/event-stream"
                    } else {
                        "application/json"
                    };
                    ([(header::CONTENT_TYPE, content_type)], "{}")
                }),
            )
            .layer(surface_cors_layer(&cors, surfaces))
            .oneshot(
                request
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    fn allow_origin(response: &axum::response::Response) -> Option<String> {
        response
            .headers()
            .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(|value| {
                value
                    .to_str()
                    .unwrap()
                    .to_string()
            })
    }

    #[tokio::test]
    async fn a_surface_browser_origin_may_call_its_own_surface_only() {
        let page = "https://chat.example.com";
        let surfaces = Arc::new(RwLock::new(vec![
            browser_origin_surface("/agents/alpha", &[page]),
            browser_origin_surface("/agents/beta", &[]),
        ]));
        for (path, event_stream) in [("/agents/alpha/rpc", false), ("/agents/alpha/stream", true)] {
            let preflight = browser_origin_response(&surfaces, &[], page, "OPTIONS", path, Some("POST")).await;
            assert_eq!(allow_origin(&preflight).as_deref(), Some(page), "preflight {path}");
            let call = browser_origin_response(&surfaces, &[], page, "POST", path, None).await;
            assert_eq!(allow_origin(&call).as_deref(), Some(page), "request {path}");
            assert_eq!(
                call.headers()[axum::http::header::CONTENT_TYPE],
                if event_stream {
                    "text/event-stream"
                } else {
                    "application/json"
                }
            );
            assert!(
                !call
                    .headers()
                    .contains_key(axum::http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            );
            assert!(
                !preflight
                    .headers()
                    .contains_key(axum::http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            );
            assert_eq!(call.headers()[axum::http::header::ACCESS_CONTROL_EXPOSE_HEADERS], "www-authenticate");
        }
        for path in ["/agents/beta/rpc", "/agents/beta/stream", "/agents/other/rpc", "/elsewhere"] {
            let preflight = browser_origin_response(&surfaces, &[], page, "OPTIONS", path, Some("POST")).await;
            assert_eq!(allow_origin(&preflight), None, "preflight {path}");
            let call = browser_origin_response(&surfaces, &[], page, "POST", path, None).await;
            assert_eq!(allow_origin(&call), None, "request {path}");
        }
        let stranger =
            browser_origin_response(&surfaces, &[], "https://evil.example", "POST", "/agents/alpha/rpc", None).await;
        assert_eq!(allow_origin(&stranger), None);
        let near_miss =
            browser_origin_response(&surfaces, &[], "https://chat.example.com:8443", "POST", "/agents/alpha/rpc", None)
                .await;
        assert_eq!(allow_origin(&near_miss), None);
    }

    #[tokio::test]
    async fn the_network_cors_list_still_applies_to_surface_paths() {
        let dashboard = "https://dashboard.example.com";
        let surfaces = Arc::new(RwLock::new(vec![browser_origin_surface("/agents/alpha", &[])]));
        for path in ["/agents/alpha/rpc", "/agents/unknown"] {
            let call = browser_origin_response(&surfaces, &[dashboard], dashboard, "POST", path, None).await;
            assert_eq!(allow_origin(&call).as_deref(), Some(dashboard), "{path}");
            let stranger =
                browser_origin_response(&surfaces, &[dashboard], "https://chat.example.com", "POST", path, None).await;
            assert_eq!(allow_origin(&stranger), None, "{path}");
        }
    }

    #[tokio::test]
    async fn public_discovery_reads_keep_their_any_origin_rule() {
        let surfaces = Arc::new(RwLock::new(vec![browser_origin_surface("/agents/alpha", &[])]));
        let read =
            browser_origin_response(&surfaces, &[], "https://anywhere.example", "GET", "/agents/alpha/discovery", None)
                .await;
        assert_eq!(allow_origin(&read).as_deref(), Some("https://anywhere.example"));
    }

    #[tokio::test]
    async fn a_saved_browser_origin_applies_to_the_next_request() {
        let page = "https://chat.example.com";
        let surfaces = Arc::new(RwLock::new(vec![browser_origin_surface("/agents/alpha", &[])]));
        let call = browser_origin_response(&surfaces, &[], page, "POST", "/agents/alpha/rpc", None).await;
        assert_eq!(allow_origin(&call), None);

        *surfaces.write().await = vec![browser_origin_surface("/agents/alpha", &[page])];
        let call = browser_origin_response(&surfaces, &[], page, "POST", "/agents/alpha/rpc", None).await;
        assert_eq!(allow_origin(&call).as_deref(), Some(page));

        *surfaces.write().await = vec![browser_origin_surface("/agents/alpha", &[])];
        let call = browser_origin_response(&surfaces, &[], page, "POST", "/agents/alpha/rpc", None).await;
        assert_eq!(allow_origin(&call), None);
    }

    #[tokio::test]
    async fn a_disabled_surface_opens_no_browser_origin() {
        let page = "https://chat.example.com";
        let mut disabled = browser_origin_surface("/agents/alpha", &[page]);
        let mut surface = (*disabled.surface).clone();
        surface.status = crate::config::agent_surface::SurfaceStatus::Disabled;
        disabled.surface = Arc::new(surface);
        let surfaces = Arc::new(RwLock::new(vec![disabled]));
        let call = browser_origin_response(&surfaces, &[], page, "POST", "/agents/alpha/rpc", None).await;
        assert_eq!(allow_origin(&call), None);
    }

    #[tokio::test]
    async fn the_most_specific_surface_route_decides_the_browser_origin() {
        let page = "https://chat.example.com";
        let surfaces = Arc::new(RwLock::new(vec![
            browser_origin_surface("/agents", &[page]),
            browser_origin_surface("/agents/beta", &[]),
        ]));
        let outer = browser_origin_response(&surfaces, &[], page, "POST", "/agents/alpha/rpc", None).await;
        assert_eq!(allow_origin(&outer).as_deref(), Some(page));
        let inner = browser_origin_response(&surfaces, &[], page, "POST", "/agents/beta/rpc", None).await;
        assert_eq!(allow_origin(&inner), None);
    }

    #[test]
    fn proxy_cors_keeps_allowlist_for_a_non_read_on_a_discovery_like_path() {
        let origin = HeaderValue::from_static("https://evil.example");
        let origins = vec![HeaderValue::from_static("https://dashboard.example.com")];

        assert!(!is_proxy_cors_origin_allowed(&origin, "POST", "/agents/copilot-worker/agent.json", &origins));
        assert!(!is_proxy_cors_origin_allowed(&origin, "POST", "/agents/copilot-worker/discovery", &origins));
        assert!(is_proxy_cors_origin_allowed(
            &HeaderValue::from_static("https://dashboard.example.com"),
            "POST",
            "/agents/copilot-worker/agent.json",
            &origins,
        ));
    }

    #[tokio::test]
    async fn proxy_cors_preflight_is_judged_by_the_requested_method() {
        use axum::http::{Request, StatusCode, header};
        use tower::ServiceExt;
        let app = Router::new()
            .route("/{*path}", axum::routing::any(|| async { StatusCode::OK }))
            .layer(proxy_cors_layer(&["https://dashboard.example.com".to_string()]));
        let preflight = |method: &'static str| {
            Request::builder()
                .method("OPTIONS")
                .uri("/agents/copilot-worker/agent.json")
                .header(header::ORIGIN, "https://evil.example")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, method)
                .body(axum::body::Body::empty())
                .unwrap()
        };

        let get = app
            .clone()
            .oneshot(preflight("GET"))
            .await
            .unwrap();
        let post = app
            .oneshot(preflight("POST"))
            .await
            .unwrap();

        assert!(
            get.headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        );
        assert!(
            !post
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        );
    }

    #[tokio::test]
    async fn an_access_point_answer_carries_no_cookie_the_target_set() {
        use axum::http::{Request, StatusCode, header};
        use tower::ServiceExt;
        let app = Router::new()
            .route(
                "/{*path}",
                axum::routing::any(|| async {
                    (
                        [
                            (header::SET_COOKIE, "__Host-session_token=planted; Path=/; Secure"),
                            (header::SET_COOKIE, "lb=sticky"),
                            (header::HeaderName::from_static("set-cookie2"), "legacy=1"),
                            (header::CACHE_CONTROL, "no-store"),
                        ],
                        StatusCode::OK,
                    )
                }),
            )
            .layer(axum::middleware::map_response(withhold_target_cookies));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/agents/worker/rpc")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            !response
                .headers()
                .contains_key(header::SET_COOKIE)
        );
        assert!(
            !response
                .headers()
                .contains_key("set-cookie2")
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[test]
    fn proxy_cors_keeps_allowlist_for_non_discovery_paths() {
        let origin = HeaderValue::from_static("https://copilotstudio.microsoft.com");
        let origins = vec![HeaderValue::from_static("https://dashboard.example.com")];

        assert!(!is_proxy_cors_origin_allowed(&origin, "POST", "/agents/copilot-worker/rpc", &origins));
    }

    #[tokio::test]
    async fn channel_alive_route_returns_ok() {
        use axum::body::{Body, to_bytes};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        // Mirrors the `/alive` route registered on the outbound/channel listener
        // in `build_outbound_port_router` (used by ECS/ALB health checks on the
        // channel port, e.g. 5000).
        let app = Router::new().route("/alive", axum::routing::get(crate::identity::handlers::alive_check));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/alive")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        assert_eq!(&body[..], br#"{"status":"OK"}"#);
    }

    #[test]
    fn join_empty_host_empty_route_returns_fabric() {
        assert_eq!(join_host_and_route("", ""), "fabric");
    }

    #[test]
    fn join_empty_host_slash_route_returns_fabric() {
        assert_eq!(join_host_and_route("", "/"), "fabric");
    }

    #[test]
    fn join_empty_host_with_absolute_route() {
        assert_eq!(join_host_and_route("", "/api/v1"), "fabric/api/v1");
    }

    #[test]
    fn join_empty_host_with_relative_route() {
        assert_eq!(join_host_and_route("", "api/v1"), "fabric/api/v1");
    }

    #[test]
    fn join_host_with_empty_route() {
        assert_eq!(join_host_and_route("https://example.com", ""), "https://example.com");
    }

    #[test]
    fn join_host_with_slash_route() {
        assert_eq!(join_host_and_route("https://example.com", "/"), "https://example.com");
    }

    #[test]
    fn join_host_with_absolute_route() {
        assert_eq!(join_host_and_route("https://example.com", "/api/v1"), "https://example.com/api/v1");
    }

    #[test]
    fn join_host_with_relative_route() {
        assert_eq!(join_host_and_route("https://example.com", "api/v1"), "https://example.com/api/v1");
    }

    #[test]
    fn join_host_trailing_slash_with_absolute_route() {
        assert_eq!(join_host_and_route("https://example.com/", "/api/v1"), "https://example.com/api/v1");
    }

    #[test]
    fn join_host_trailing_slash_with_relative_route() {
        assert_eq!(join_host_and_route("https://example.com/", "api/v1"), "https://example.com/api/v1");
    }

    #[test]
    fn join_host_trailing_slash_empty_route() {
        assert_eq!(join_host_and_route("https://example.com/", ""), "https://example.com");
    }

    const SURFACE_TARGET_ENDPOINT: &str = "http://surface-target.example.com";

    fn outbound_surface_with_transit_point(
        surface_id: &str,
        tp_target_endpoint: &str,
        tp_listen_path: Option<&str>,
    ) -> crate::config::agent_surface::AgentSurface {
        use crate::config::agent_surface::{
            AccessPoint, AgentSurface, SharedTransitConfig, SurfaceProtocol, Target, TransitConfig, TransitPoint,
            TransitProtocol,
        };

        AgentSurface {
            surface_id: surface_id.to_string(),
            name: "outbound-channel".to_string(),
            access_point: AccessPoint {
                listen_address: "0.0.0.0:8443".to_string(),
                route: "/surfaces/order".to_string(),
                protocol: SurfaceProtocol::A2a,
                ..Default::default()
            },
            target: Target {
                endpoint: SURFACE_TARGET_ENDPOINT.to_string(),
                ..Default::default()
            },
            transit: Some(TransitConfig {
                points: vec![TransitPoint {
                    id: "tp-partner-a".to_string(),
                    name: "Partner A".to_string(),
                    alias: "partner-a".to_string(),
                    target_endpoint: tp_target_endpoint.to_string(),
                    protocol: TransitProtocol::A2a,
                    mcp_http: None,
                    header_metadata_mapping: None,
                    target_auth: None,
                    policy: None,
                    response_policy: None,
                    mcp_tool_gating: None,
                    payment_policy: None,
                    networking: None,
                    rate_limit: None,
                    per_caller_rate_limit: None,
                    identity_injection: Default::default(),
                    managed_identity: None,
                    transit_credentials: None,
                    workload_binding: None,
                    gateway_url: "https://gw.internal:9000/outbound/surfaces/order/partner-a".to_string(),
                    agent_card_path: None,
                    listen_address: None,
                    listen_path: tp_listen_path.map(str::to_string),
                    require_transit_token: true,
                    source_auth: None,
                    allow_unauthenticated_callers: false,
                    extension_inspection: crate::config::types::ExtensionInspectionConfig::default(),
                    fabric_delegated_credentials: false,
                    delegated_credentials_for_fabric_callers: false,
                    trust_check_list: Vec::new(),
                    trust_check_migrated: false,
                }],
                outbound_listen_address: None,
                shared: SharedTransitConfig::default(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn outbound_state_creates_entry_for_new_config_id() {
        let mut states = std::collections::HashMap::new();
        let surface = outbound_surface_with_transit_point("cfg-1", "http://localhost:9000", None);

        let created_state = get_or_create_outbound_channel_state(&mut states, "cfg-1", &surface, None, None);

        assert_eq!(states.len(), 1);
        assert!(states.contains_key("cfg-1"));
        assert_eq!(
            created_state
                .read()
                .unwrap()
                .surface
                .config_id(),
            Some("cfg-1")
        );
    }

    #[test]
    fn outbound_state_keeps_variant_catalog_on_reload() {
        let mut states = std::collections::HashMap::new();
        let mut surface = outbound_surface_with_transit_point("cfg-1", "https://base.example/mcp", None);
        let handler_state = get_or_create_outbound_channel_state(&mut states, "cfg-1", &surface, None, None);
        for revision in ["initial", "updated"] {
            let mut default_point = surface.transit_points()[0].clone();
            default_point.target_endpoint = format!("https://default.example/{revision}");
            let mut candidate_point = default_point.clone();
            candidate_point.target_endpoint = format!("https://candidate.example/{revision}");
            surface.variants = serde_json::from_value(serde_json::json!([
                {"id": "default", "alias": "default", "name": "Default", "overrides": {
                    "transit": {"points": [default_point]}
                }},
                {"id": "candidate", "alias": "candidate", "name": "Candidate", "overrides": {
                    "transit": {"points": [candidate_point]}
                }}
            ]))
            .unwrap();
            surface.default_variant_id = Some("default".into());
            let reloaded = get_or_create_outbound_channel_state(&mut states, "cfg-1", &surface, None, None);
            assert!(Arc::ptr_eq(&handler_state, &reloaded));
            let live = handler_state
                .read()
                .unwrap()
                .surface
                .clone();
            assert_eq!(live.variants.len(), 2);
            assert_eq!(
                live.default_variant_id
                    .as_deref(),
                Some("default")
            );
            assert_eq!(
                live.resolve_variant(None)
                    .unwrap()
                    .transit_points()[0]
                    .target_endpoint,
                default_point.target_endpoint
            );
            assert_eq!(
                live.resolve_variant(Some("candidate"))
                    .unwrap()
                    .transit_points()[0]
                    .target_endpoint,
                candidate_point.target_endpoint
            );
            assert!(
                live.resolve_variant(Some("missing"))
                    .is_err()
            );
        }
    }

    #[test]
    fn outbound_state_updates_transit_point_target_in_place() {
        let mut states = std::collections::HashMap::new();
        let original_tp_target = "https://partner-old.example.com/a2a";
        let reloaded_tp_target = "https://partner-new.example.com/a2a";

        // First registration creates the shared Arc that route handlers hold.
        let original_surface = outbound_surface_with_transit_point("cfg-1", original_tp_target, None);
        assert_eq!(original_surface.target_endpoint(), SURFACE_TARGET_ENDPOINT);
        assert_eq!(original_surface.transit_points()[0].target_endpoint, original_tp_target);
        let handler_state = get_or_create_outbound_channel_state(&mut states, "cfg-1", &original_surface, None, None);

        assert_eq!(states.len(), 1);
        assert_eq!(
            handler_state
                .read()
                .unwrap()
                .surface
                .transit_points()[0]
                .target_endpoint,
            original_tp_target
        );

        // Reloading the same config id updates the TP target in the same Arc.
        let reloaded_surface = outbound_surface_with_transit_point("cfg-1", reloaded_tp_target, None);
        assert_eq!(reloaded_surface.target_endpoint(), SURFACE_TARGET_ENDPOINT);
        assert_eq!(reloaded_surface.transit_points()[0].target_endpoint, reloaded_tp_target);
        let reloaded_state = get_or_create_outbound_channel_state(&mut states, "cfg-1", &reloaded_surface, None, None);

        assert_eq!(states.len(), 1);
        assert!(Arc::ptr_eq(&handler_state, &reloaded_state));
        assert_eq!(
            reloaded_state
                .read()
                .unwrap()
                .surface
                .transit_points()[0]
                .target_endpoint,
            reloaded_tp_target
        );
        assert_eq!(
            handler_state
                .read()
                .unwrap()
                .surface
                .transit_points()[0]
                .target_endpoint,
            reloaded_tp_target
        );

        let updated_surface = reloaded_state
            .read()
            .unwrap()
            .surface
            .clone();
        assert_eq!(updated_surface.target_endpoint(), SURFACE_TARGET_ENDPOINT);
    }

    #[test]
    fn outbound_state_updates_transit_point_listen_path_in_place() {
        let mut states = std::collections::HashMap::new();
        let tp_target = "https://partner.example.com/a2a";
        let original_listen_path = "/old-partner-webhook";
        let reloaded_listen_path = "/new-partner-webhook";

        // Existing route handlers hold this shared state while Axum routes are rebuilt separately.
        let original_surface = outbound_surface_with_transit_point("cfg-1", tp_target, Some(original_listen_path));
        assert_eq!(
            original_surface.transit_points()[0]
                .listen_path
                .as_deref(),
            Some(original_listen_path)
        );
        let handler_state = get_or_create_outbound_channel_state(&mut states, "cfg-1", &original_surface, None, None);

        assert_eq!(
            handler_state
                .read()
                .unwrap()
                .surface
                .transit_points()[0]
                .listen_path
                .as_deref(),
            Some(original_listen_path)
        );

        // Reloading the same config id replaces the TP list in the same Arc.
        let reloaded_surface = outbound_surface_with_transit_point("cfg-1", tp_target, Some(reloaded_listen_path));
        assert_eq!(
            reloaded_surface.transit_points()[0]
                .listen_path
                .as_deref(),
            Some(reloaded_listen_path)
        );
        let reloaded_state = get_or_create_outbound_channel_state(&mut states, "cfg-1", &reloaded_surface, None, None);

        assert_eq!(states.len(), 1);
        assert!(Arc::ptr_eq(&handler_state, &reloaded_state));
        assert_eq!(
            reloaded_state
                .read()
                .unwrap()
                .surface
                .transit_points()[0]
                .listen_path
                .as_deref(),
            Some(reloaded_listen_path)
        );
        assert_eq!(
            handler_state
                .read()
                .unwrap()
                .surface
                .transit_points()[0]
                .listen_path
                .as_deref(),
            Some(reloaded_listen_path)
        );
        assert_eq!(
            handler_state
                .read()
                .unwrap()
                .surface
                .transit_points()[0]
                .target_endpoint,
            tp_target
        );
    }

    #[test]
    fn outbound_state_keeps_config_ids_isolated() {
        let mut states = std::collections::HashMap::new();
        let surface_a = outbound_surface_with_transit_point("cfg-a", "http://localhost:9000", None);
        let surface_b = outbound_surface_with_transit_point("cfg-b", "http://localhost:9001", None);

        let state_a = get_or_create_outbound_channel_state(&mut states, "cfg-a", &surface_a, None, None);
        let state_b = get_or_create_outbound_channel_state(&mut states, "cfg-b", &surface_b, None, None);

        assert_eq!(states.len(), 2);
        assert!(!Arc::ptr_eq(&state_a, &state_b));
        assert_eq!(
            state_a
                .read()
                .unwrap()
                .surface
                .config_id(),
            Some("cfg-a")
        );
        assert_eq!(
            state_b
                .read()
                .unwrap()
                .surface
                .config_id(),
            Some("cfg-b")
        );
    }

    // ── find_shared_outbound_listener + extract_hostname ──────────────────

    fn make_network_config_with_listeners(
        inbound_urls: Vec<&str>,
        outbound_urls: Vec<&str>,
    ) -> crate::config::NetworkConfig {
        network_config_binding("0.0.0.0", inbound_urls, "0.0.0.0", outbound_urls)
    }

    /// An inbound listener on port 8080 and an outbound one on 9000, bound to
    /// the given addresses.
    fn network_config_binding(
        inbound_bind: &str,
        inbound_urls: Vec<&str>,
        outbound_bind: &str,
        outbound_urls: Vec<&str>,
    ) -> crate::config::NetworkConfig {
        serde_json::from_value(serde_json::json!({
            "did": { "domain": "test.example.com" },
            "webauthn": { "rp_id": "test", "external_origin": "https://test.example.com" },
            "integration": { "types": [], "categories": [] },
            "listeners": [
                {
                    "id": "inbound-http",
                    "name": "Inbound",
                    "bind_address": inbound_bind,
                    "port": 8080,
                    "protocol": "http",
                    "external_urls": inbound_urls,
                    "listener_type": "inbound"
                },
                {
                    "id": "outbound-http",
                    "name": "Outbound",
                    "bind_address": outbound_bind,
                    "port": 9000,
                    "protocol": "http",
                    "external_urls": outbound_urls,
                    "listener_type": "outbound"
                }
            ],
            "routes": {}
        }))
        .expect("make_network_config_with_listeners")
    }

    #[test]
    fn an_inbound_listener_binds_its_configured_address() {
        let config: crate::config::NetworkConfig = serde_json::from_value(serde_json::json!({
            "did": { "domain": "test.example.com" },
            "webauthn": { "rp_id": "test", "external_origin": "https://test.example.com" },
            "integration": { "types": [], "categories": [] },
            "listeners": [
                { "id": "loopback", "name": "Loopback", "bind_address": "127.0.0.1", "port": 8080,
                    "protocol": "http", "external_urls": [] },
                { "id": "loopback-v6", "name": "Loopback v6", "bind_address": "::1", "port": 8443,
                    "protocol": "https", "external_urls": [] },
                { "id": "every-interface", "name": "Every interface", "bind_address": "0.0.0.0", "port": 8081,
                    "protocol": "http", "external_urls": [] },
                { "id": "internal", "name": "Internal", "bind_address": "10.0.0.5", "port": 8444,
                    "protocol": "https", "external_urls": [] },
                { "id": "sidecar", "name": "Sidecar", "bind_address": "127.0.0.1", "port": 8444,
                    "protocol": "https", "external_urls": [] },
                { "id": "narrow", "name": "Narrow", "bind_address": "127.0.0.1", "port": 8445,
                    "protocol": "http", "external_urls": [] },
                { "id": "wide-v4", "name": "Wide v4", "bind_address": "0.0.0.0", "port": 8445,
                    "protocol": "http", "external_urls": [] },
                { "id": "wide-v6", "name": "Wide v6", "bind_address": "::", "port": 8445,
                    "protocol": "http", "external_urls": [] },
                { "id": "outbound", "name": "Outbound", "bind_address": "10.0.0.9", "port": 8446,
                    "protocol": "http", "external_urls": [], "listener_type": "outbound" },
                { "id": "inbound-beside-outbound", "name": "Inbound", "bind_address": "127.0.0.1", "port": 8446,
                    "protocol": "http", "external_urls": [] }
            ],
            "routes": {}
        }))
        .unwrap();

        for (port, expected) in [
            (8080, vec!["127.0.0.1:8080"]),
            (8443, vec!["[::1]:8443"]),
            (8081, vec!["0.0.0.0:8081"]),
            (8444, vec!["10.0.0.5:8444", "127.0.0.1:8444"]),
            (8445, vec!["[::]:8445", "0.0.0.0:8445", "127.0.0.1:8445"]),
            (8446, vec!["127.0.0.1:8446"]),
        ] {
            assert_eq!(
                inbound_bind_addresses(&config, port).unwrap(),
                expected
                    .iter()
                    .map(|address| {
                        address
                            .parse::<SocketAddr>()
                            .unwrap()
                    })
                    .collect::<Vec<_>>(),
                "{port}"
            );
        }
        assert_eq!(config.get_ports(), vec![8080, 8443, 8081, 8444, 8445, 8446]);
        assert_eq!(
            inbound_bind_addresses(&config, 9999)
                .unwrap_err()
                .to_string(),
            "No inbound listener is configured for port 9999",
            "a port without an inbound listener is never bound on every interface"
        );
        let outbound_only = make_network_config_with_listeners(vec![], vec![]);
        assert!(inbound_bind_addresses(&outbound_only, 9000).is_err());
    }

    #[test]
    fn a_bound_address_covers_only_what_its_socket_accepts() {
        let address = |value: &str| {
            value
                .parse::<SocketAddr>()
                .unwrap()
        };
        let dual_stack = false;
        let ipv6_only = true;

        assert!(bound_address_covers(address("0.0.0.0:80"), ipv6_only, address("127.0.0.1:80")));
        assert!(bound_address_covers(address("0.0.0.0:80"), ipv6_only, address("0.0.0.0:80")));
        assert!(bound_address_covers(address("[::]:80"), ipv6_only, address("[::1]:80")));
        assert!(bound_address_covers(address("[::]:80"), dual_stack, address("0.0.0.0:80")));
        assert!(bound_address_covers(address("[::]:80"), dual_stack, address("10.0.0.5:80")));

        assert!(!bound_address_covers(address("[::]:80"), ipv6_only, address("0.0.0.0:80")));
        assert!(!bound_address_covers(address("[::]:80"), ipv6_only, address("127.0.0.1:80")));
        assert!(!bound_address_covers(address("0.0.0.0:80"), ipv6_only, address("[::1]:80")));
        assert!(!bound_address_covers(address("0.0.0.0:80"), ipv6_only, address("[::]:80")));
        assert!(!bound_address_covers(address("127.0.0.1:80"), ipv6_only, address("127.0.0.1:80")));
        assert!(!bound_address_covers(address("[::1]:80"), dual_stack, address("127.0.0.1:80")));
        assert!(!bound_address_covers(address("0.0.0.0:80"), ipv6_only, address("127.0.0.1:81")));
    }

    #[test]
    fn a_listener_binds_an_ipv4_or_ipv6_bind_address() {
        for (bind_address, expected) in
            [("127.0.0.1", "127.0.0.1:9000"), ("::1", "[::1]:9000"), ("::", "[::]:9000"), ("0.0.0.0", "0.0.0.0:9000")]
        {
            assert_eq!(
                listener_socket_address(bind_address, 9000).unwrap(),
                expected
                    .parse::<SocketAddr>()
                    .unwrap(),
                "{bind_address}"
            );
        }
        assert!(listener_socket_address("localhost", 9000).is_err());
        assert!(listener_socket_address("[1.2.3.4]", 9000).is_err());
        assert_eq!(
            listener_socket_address("[::1]", 9000).unwrap(),
            "[::1]:9000"
                .parse::<SocketAddr>()
                .unwrap()
        );
        assert_eq!(
            format!("http://{}", listener_socket_address("::1", 9000).unwrap()),
            "http://[::1]:9000",
            "the shared-domain proxy reaches an IPv6 outbound listener at a URL that parses"
        );
    }

    #[tokio::test]
    async fn an_outbound_listener_binds_an_ipv6_bind_address() {
        let Ok(probe) = std::net::TcpListener::bind("[::1]:0") else {
            eprintln!("skipped: this host has no IPv6 loopback address");
            return;
        };
        let port = probe
            .local_addr()
            .unwrap()
            .port();
        drop(probe);
        let config: GatewayConfig = serde_json::from_value(serde_json::json!({
            "tls": {"cert_path": "unused.pem", "key_path": "unused-key.pem"},
            "integration": {"variable_pattern": "\\$\\{([^}]+)\\}", "custom_variable_prefix": "_", "types": [],
                "categories": []},
            "extension_inspection": {"enabled": false}
        }))
        .unwrap();
        let router = build_outbound_port_router(
            port,
            Vec::new(),
            Arc::new(config),
            Arc::new(make_network_config_with_listeners(vec![], vec![])),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            Arc::new(tokio::sync::RwLock::new(None)),
            None,
        )
        .await
        .unwrap();
        let _server = crate::proxy::port_listener::BoundPort::bind(
            port,
            crate::proxy::port_listener::PortBinding {
                addresses: vec![listener_socket_address("::1", port).unwrap()],
                tls: false,
            },
            router,
            None,
            false,
        )
        .await
        .unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();

        let mut alive = None;
        for _ in 0..50 {
            if let Ok(response) = client
                .get(format!("http://[::1]:{port}/alive"))
                .send()
                .await
            {
                alive = Some(response.status());
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        assert_eq!(alive, Some(reqwest::StatusCode::OK));
    }

    #[tokio::test]
    async fn an_outbound_router_registers_its_surface_states_before_it_is_returned() {
        let config: GatewayConfig = serde_json::from_value(serde_json::json!({
            "tls": {"cert_path": "unused.pem", "key_path": "unused-key.pem"},
            "integration": {"variable_pattern": "\\$\\{([^}]+)\\}", "custom_variable_prefix": "_", "types": [],
                "categories": []},
            "extension_inspection": {"enabled": false}
        }))
        .unwrap();
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "fresh", "name": "fresh", "status": "active",
            "access_point": { "listen_address": "http://localhost:8080", "route": "/fresh", "protocol": "a2a" },
            "target": { "endpoint": "http://localhost:9001" },
            "transit": { "outbound_listen_address": "http://localhost:9000",
                "points": [{ "alias": "partner", "target_endpoint": "http://localhost:9002" }] }
        }))
        .unwrap();
        let points = surface
            .transit
            .as_ref()
            .unwrap()
            .points
            .clone();
        let states = Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));

        let _router = build_outbound_port_router(
            0,
            vec![(surface, points)],
            Arc::new(config),
            Arc::new(make_network_config_with_listeners(vec![], vec![])),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            states.clone(),
            Arc::new(tokio::sync::RwLock::new(None)),
            None,
        )
        .await
        .unwrap();
        let registered: Vec<String> = states
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect();

        assert_eq!(registered, ["fresh"]);
    }

    #[tokio::test]
    async fn a_port_binds_each_inbound_address_and_skips_one_its_wildcard_already_serves() {
        let held = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let port = held
            .local_addr()
            .unwrap()
            .port();
        let loopback = SocketAddr::from(([127, 0, 0, 1], port));

        let error = bind_inbound_listeners(&[loopback])
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("Failed to bind inbound listener 127.0.0.1:"),
            "{error}"
        );
        drop(held);

        let listeners = bind_inbound_listeners(&[SocketAddr::from(([0, 0, 0, 0], port)), loopback])
            .await
            .unwrap();
        assert!(
            listeners
                .iter()
                .any(|listener| listener
                    .local_addr()
                    .unwrap()
                    .ip()
                    .is_unspecified())
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), tokio::net::TcpStream::connect(loopback))
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn extract_hostname_strips_scheme_port_and_path() {
        assert_eq!(extract_hostname("https://example.com/path"), Some("example.com".to_string()));
        assert_eq!(extract_hostname("http://example.com:8080/foo"), Some("example.com".to_string()));
        assert_eq!(extract_hostname("https://Example.COM"), Some("example.com".to_string()));
        assert_eq!(extract_hostname("no-scheme"), None);
        assert_eq!(extract_hostname("http://10.0.0.1:8080/x"), Some("10.0.0.1".to_string()));
        assert_eq!(extract_hostname("https://[2001:db8::1]:8443/x"), Some("[2001:db8::1]".to_string()));
        assert_eq!(extract_hostname("https://[::1]"), Some("[::1]".to_string()));
        assert_eq!(extract_hostname("https://[2001:DB8:0:0::1]"), Some("[2001:db8::1]".to_string()));
        assert_eq!(extract_hostname("https://[2001:db8::1"), None);
    }

    #[test]
    fn find_shared_outbound_listener_never_matches_different_ipv6_hosts() {
        for (inbound, outbound) in [
            ("https://[2001:db8::1]:8443", "https://[2001:db8::2]:9443"),
            ("https://[::1]", "https://[::2]"),
            ("https://[2001:db8::1]", "https://[2001:db9::1]"),
        ] {
            let config = make_network_config_with_listeners(vec![inbound], vec![outbound]);
            assert!(find_shared_outbound_listener(&config, 8080).is_none(), "{inbound} and {outbound}");
        }
    }

    #[test]
    fn find_shared_outbound_listener_matches_one_ipv6_host_however_it_is_written() {
        let config = make_network_config_with_listeners(
            vec!["https://[2001:db8::1]:8443"],
            vec!["https://[2001:DB8:0:0:0:0:0:1]:9443"],
        );
        assert!(find_shared_outbound_listener(&config, 8080).is_some());
    }

    #[test]
    fn find_shared_outbound_listener_returns_none_for_distinct_domains() {
        let config = make_network_config_with_listeners(
            vec!["https://inbound.example.com", "http://localhost:8080"],
            vec!["https://outbound.example.com"],
        );
        assert!(find_shared_outbound_listener(&config, 8080).is_none());
    }

    #[test]
    fn find_shared_outbound_listener_returns_outbound_when_hostname_overlaps() {
        // robert-fabric-1 appears in both inbound and outbound
        let config = make_network_config_with_listeners(
            vec!["https://shared.example.com", "http://localhost:8080"],
            vec!["https://outbound.example.com", "https://shared.example.com", "http://localhost:9000"],
        );
        let found = find_shared_outbound_listener(&config, 8080);
        assert!(found.is_some(), "should find shared outbound listener");
        assert_eq!(found.unwrap().port, 9000);
    }

    #[test]
    fn find_shared_outbound_listener_ignores_port_differences_in_url() {
        // Same hostname, different port numbers — still considered shared
        let config = make_network_config_with_listeners(
            vec!["https://shared.example.com:443"],
            vec!["https://shared.example.com:9000"],
        );
        assert!(find_shared_outbound_listener(&config, 8080).is_some());
    }

    #[test]
    fn find_shared_outbound_listener_returns_none_for_localhost_only_inbound() {
        // localhost on inbound does NOT match a public-only outbound URL
        let config =
            make_network_config_with_listeners(vec!["http://localhost:8080"], vec!["https://outbound.example.com"]);
        // localhost:8080 inbound vs outbound.example.com → no overlap
        assert!(find_shared_outbound_listener(&config, 8080).is_none());
    }

    #[test]
    fn find_shared_outbound_listener_is_case_insensitive() {
        let config =
            make_network_config_with_listeners(vec!["https://Shared.Example.COM"], vec!["https://shared.example.com"]);
        assert!(find_shared_outbound_listener(&config, 8080).is_some());
    }

    #[test]
    fn the_outbound_proxy_on_an_inbound_listener_never_passes_a_forwarded_client_certificate() {
        for header in ["X-Forwarded-Client-Cert", "x-forwarded-client-cert"] {
            assert!(!shared_domain_proxy_forwards(header, "x-forwarded-client-cert"), "{header}");
        }
        assert!(!shared_domain_proxy_forwards("x-client-cert", "X-Client-Cert"));
        for header in ["host", "connection", "transfer-encoding"] {
            assert!(!shared_domain_proxy_forwards(header, "x-forwarded-client-cert"), "{header}");
        }
        for header in ["x-transit-token", "x-api-key", "authorization", "content-type"] {
            assert!(shared_domain_proxy_forwards(header, "x-forwarded-client-cert"), "{header}");
        }
    }

    #[test]
    fn only_this_hosts_own_addresses_are_out_of_reach_of_other_hosts() {
        for url in [
            "https://gateway.example.com",
            "https://gateway.internal:9000/outbound",
            "http://203.0.113.7:9000",
            "http://[2001:db8::1]:9000",
            "http://10.1.2.3",
            "http://172.16.0.1",
            "http://192.168.1.10",
            "http://169.254.169.254",
            "http://[fd00::1]",
            "http://[fe80::1]",
            "http://[::ffff:10.0.0.1]",
            "not a url",
        ] {
            assert!(reachable_from_other_hosts(url), "{url}");
        }
        for url in [
            "http://localhost:9000",
            "http://LOCALHOST:9000",
            "http://gateway.localhost",
            "http://127.0.0.1:9000",
            "http://127.8.0.1",
            "http://0.0.0.0:9000",
            "http://[::1]:9000",
            "http://[::ffff:127.0.0.1]",
        ] {
            assert!(!reachable_from_other_hosts(url), "{url}");
        }
    }

    #[test]
    fn an_outbound_listener_is_exposed_on_its_urls_its_bind_address_and_an_inbound_listener_sharing_its_host() {
        let loopback =
            |inbound_urls, outbound_urls| network_config_binding("127.0.0.1", inbound_urls, "127.0.0.1", outbound_urls);
        let addresses = |addresses: &[&str]| -> Vec<String> {
            addresses
                .iter()
                .map(|address| address.to_string())
                .collect()
        };
        let separate = loopback(vec!["https://inbound.example.com"], vec!["http://localhost:9000"]);
        assert_eq!(exposed_outbound_addresses(&separate, 9000), addresses(&[]));

        let own = loopback(
            vec!["https://inbound.example.com"],
            vec!["https://outbound.example.com", "http://localhost:9000"],
        );
        assert_eq!(exposed_outbound_addresses(&own, 9000), addresses(&["https://outbound.example.com"]));

        let private = loopback(vec!["https://inbound.example.com"], vec!["http://10.0.0.5:9000"]);
        assert_eq!(
            exposed_outbound_addresses(&private, 9000),
            addresses(&["http://10.0.0.5:9000"]),
            "every workload on that network reaches a private address"
        );

        let shared =
            loopback(vec!["https://gateway.example.com", "http://localhost:8080"], vec!["http://localhost:9000"]);
        assert_eq!(
            exposed_outbound_addresses(&shared, 9000),
            addresses(&["https://gateway.example.com"]),
            "the inbound listener passes /outbound to the outbound listener it shares localhost with"
        );
        assert_eq!(exposed_outbound_addresses(&shared, 9001), addresses(&[]));

        let bound = network_config_binding(
            "127.0.0.1",
            vec!["https://inbound.example.com"],
            "0.0.0.0",
            vec!["http://localhost:9000"],
        );
        assert_eq!(
            exposed_outbound_addresses(&bound, 9000),
            addresses(&["0.0.0.0:9000"]),
            "a listener bound beyond loopback is reachable whatever its URLs say"
        );
        let bound_v6 = network_config_binding(
            "127.0.0.1",
            vec!["https://inbound.example.com"],
            "::",
            vec!["http://localhost:9000"],
        );
        assert_eq!(exposed_outbound_addresses(&bound_v6, 9000), addresses(&["[::]:9000"]));
        let bracketed_loopback = network_config_binding(
            "127.0.0.1",
            vec!["https://inbound.example.com"],
            "[::1]",
            vec!["http://localhost:9000"],
        );
        assert_eq!(
            exposed_outbound_addresses(&bracketed_loopback, 9000),
            addresses(&[]),
            "a bracketed IPv6 loopback bind address is loopback"
        );
        let bracketed_wildcard = network_config_binding(
            "127.0.0.1",
            vec!["https://inbound.example.com"],
            "[::]",
            vec!["http://localhost:9000"],
        );
        assert_eq!(exposed_outbound_addresses(&bracketed_wildcard, 9000), addresses(&["[::]:9000"]));

        let shared_bound = network_config_binding(
            "0.0.0.0",
            vec!["http://localhost:8080"],
            "127.0.0.1",
            vec!["http://localhost:9000"],
        );
        assert_eq!(exposed_outbound_addresses(&shared_bound, 9000), addresses(&["0.0.0.0:8080"]));
        let separate_bound = network_config_binding(
            "0.0.0.0",
            vec!["https://inbound.example.com"],
            "127.0.0.1",
            vec!["http://localhost:9000"],
        );
        assert_eq!(
            exposed_outbound_addresses(&separate_bound, 9000),
            addresses(&[]),
            "an inbound listener that does not pass /outbound on does not expose it"
        );
    }

    #[test]
    fn open_transit_points_name_the_addresses_other_hosts_reach_them_on() {
        let network = network_config_binding(
            "127.0.0.1",
            vec!["https://gateway.example.com", "http://localhost:8080"],
            "127.0.0.1",
            vec!["http://localhost:9000"],
        );
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(serde_json::json!({
            "name": "exposure",
            "access_point": { "listen_address": "http://localhost:8080", "route": "/exposure", "protocol": "a2a" },
            "target": { "endpoint": "https://agent.internal" },
            "transit": {
                "outbound_listen_address": "http://localhost:9000",
                "points": [
                    { "alias": "open", "target_endpoint": "https://open.example", "require_transit_token": false,
                        "allow_unauthenticated_callers": true },
                    { "alias": "tokened", "target_endpoint": "https://tokened.example" },
                    { "alias": "elsewhere", "target_endpoint": "https://elsewhere.example",
                        "listen_address": "http://unknown:1", "require_transit_token": false,
                        "allow_unauthenticated_callers": true }
                ]
            },
            "variants": [{ "id": "candidate", "alias": "candidate", "name": "Candidate", "overrides": {
                "transit": { "points": [{ "alias": "tokened", "target_endpoint": "https://tokened.example",
                    "require_transit_token": false, "allow_unauthenticated_callers": true }] }
            }}]
        }))
        .unwrap();
        let exposed = vec!["https://gateway.example.com".to_string()];

        let open = open_transit_points(&network, &surface);

        assert_eq!(
            open,
            vec![
                OpenTransitPoint {
                    alias: "open".to_string(),
                    variant: None,
                    port: Some(9000),
                    exposed_at: exposed.clone(),
                },
                OpenTransitPoint {
                    alias: "elsewhere".to_string(),
                    variant: None,
                    port: Some(9000),
                    exposed_at: exposed.clone(),
                },
                OpenTransitPoint {
                    alias: "tokened".to_string(),
                    variant: Some("candidate".to_string()),
                    port: Some(9000),
                    exposed_at: exposed,
                },
            ]
        );
        assert_eq!(
            open[2].exposure().unwrap(),
            "Transit Point 'tokened' in variant 'candidate' serves callers it does not authenticate and is \
             reachable from other hosts: https://gateway.example.com"
        );

        let local = network_config_binding(
            "127.0.0.1",
            vec!["http://localhost:8080"],
            "127.0.0.1",
            vec!["http://localhost:9000"],
        );
        let open = open_transit_points(&local, &surface);
        assert_eq!(open.len(), 3);
        assert!(
            open.iter()
                .all(|point| point.exposure().is_none()),
            "{open:?}"
        );
    }

    #[test]
    fn tp_outbound_path_prefix_is_outbound() {
        assert_eq!(
            crate::proxy::outbound_handler::TP_OUTBOUND_PATH_PREFIX,
            "/outbound",
            "changing this constant is a breaking change for all deployed transit points"
        );
    }

    /// A stand-in outbound listener: `/outbound/deny` answers 401 without
    /// reading the body, `/outbound/stream` sends one event and holds the
    /// stream open, and every other path reads the whole body and answers 201
    /// with the method and body length. `started` counts requests that arrived,
    /// `completed` those whose body was read to the end.
    struct OutboundStub {
        url: String,
        started: Arc<std::sync::atomic::AtomicUsize>,
        completed: Arc<std::sync::atomic::AtomicUsize>,
    }

    async fn outbound_stub() -> OutboundStub {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let started = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let (on_start, on_complete) = (started.clone(), completed.clone());
        let app = axum::Router::new()
            .route(
                "/outbound/deny",
                axum::routing::any(|| async { (StatusCode::UNAUTHORIZED, "Transit token missing or invalid") }),
            )
            .route(
                "/outbound/stream",
                axum::routing::any(|| async {
                    let first = futures::stream::once(async {
                        Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"data: first\n\n"))
                    });
                    axum::response::Response::builder()
                        .header("content-type", "text/event-stream")
                        .body(axum::body::Body::from_stream(first.chain(futures::stream::pending())))
                        .unwrap()
                }),
            )
            .route(
                "/outbound/stall",
                axum::routing::any(|request: axum::extract::Request| async {
                    let _ = axum::body::to_bytes(request.into_body(), usize::MAX).await;
                    futures::future::pending::<()>().await;
                }),
            )
            .fallback(move |request: axum::extract::Request| {
                let (on_start, on_complete) = (on_start.clone(), on_complete.clone());
                async move {
                    on_start.fetch_add(1, Ordering::SeqCst);
                    let method = request.method().clone();
                    match axum::body::to_bytes(request.into_body(), usize::MAX).await {
                        Ok(body) => {
                            on_complete.fetch_add(1, Ordering::SeqCst);
                            (StatusCode::CREATED, [("x-stub", "echo")], format!("{method} {}", body.len()))
                                .into_response()
                        }
                        Err(_) => StatusCode::BAD_REQUEST.into_response(),
                    }
                }
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });
        OutboundStub { url, started, completed }
    }

    fn hop_to(
        stub: &OutboundStub,
        max_body_bytes: usize,
    ) -> Arc<SharedHostHop> {
        Arc::new(SharedHostHop {
            target: stub.url.clone(),
            client: crate::http_client::shared_host_hop(SHARED_HOST_HOP_READ_IDLE).unwrap(),
            forwarded_cert_header: "x-forwarded-client-cert".to_string(),
            max_body_bytes,
        })
    }

    const HOP_CHUNK: usize = 1024;

    /// An endless body of `HOP_CHUNK`-byte chunks that counts every byte the
    /// hop pulls from it.
    fn endless_counted_body(pulled: Arc<std::sync::atomic::AtomicUsize>) -> axum::body::Body {
        axum::body::Body::from_stream(futures::stream::repeat_with(move || {
            pulled.fetch_add(HOP_CHUNK, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, std::io::Error>(bytes::Bytes::from(vec![0u8; HOP_CHUNK]))
        }))
    }

    async fn hop_call(
        hop: Arc<SharedHostHop>,
        request: axum::extract::Request,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        let response = tokio::time::timeout(std::time::Duration::from_secs(10), forward_shared_host_hop(hop, request))
            .await
            .expect("the hop must answer instead of reading an endless body");
        let status = response.status();
        let headers = response.headers().clone();
        let body = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            axum::body::to_bytes(response.into_body(), usize::MAX),
        )
        .await
        .expect("the hop response must end")
        .unwrap_or_default();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    fn hop_request(
        method: &str,
        path: &str,
        content_length: Option<usize>,
        body: axum::body::Body,
    ) -> axum::extract::Request {
        let mut request = axum::http::Request::builder()
            .method(method)
            .uri(path);
        if let Some(length) = content_length {
            request = request.header("content-length", length);
        }
        request.body(body).unwrap()
    }

    fn failing_body() -> axum::body::Body {
        axum::body::Body::from_stream(futures::stream::iter([
            Ok(bytes::Bytes::from_static(b"{\"jsonrpc\":")),
            Err(std::io::Error::other("caller reset the stream")),
        ]))
    }

    /// The hop answers its own refusals as a JSON-RPC error with no id
    /// when the request names an MCP protocol version, and as an A2A problem
    /// otherwise.
    #[tokio::test]
    async fn the_hop_answers_its_refusals_in_the_shape_of_the_callers_protocol() {
        let stub = outbound_stub().await;
        let mcp = |mut request: axum::extract::Request| {
            request
                .headers_mut()
                .insert("mcp-protocol-version", HeaderValue::from_static("2025-06-18"));
            request
        };

        for (case, request, status, message) in [
            (
                "declared oversize",
                mcp(hop_request("POST", "/outbound/echo", Some(4097), axum::body::Body::from(vec![0u8; 4097]))),
                StatusCode::PAYLOAD_TOO_LARGE,
                "MCP request body exceeds the configured limit",
            ),
            (
                "failed body",
                mcp(hop_request("POST", "/outbound/echo", None, failing_body())),
                StatusCode::BAD_REQUEST,
                "Failed to read MCP request body",
            ),
        ] {
            let (answered, headers, body) = hop_call(hop_to(&stub, 4096), request).await;
            assert_eq!(answered, status, "{case}: {body}");
            assert_eq!(headers["content-type"], "application/json", "{case}");
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(body["jsonrpc"], "2.0", "{case}");
            assert!(body.get("id").is_none(), "{case}: {body}");
            assert_eq!(body["error"]["code"], crate::mcp::error_codes::INVALID_REQUEST, "{case}");
            assert_eq!(body["error"]["message"], message, "{case}");
        }

        for (case, request, status) in [
            (
                "declared oversize",
                hop_request("POST", "/outbound/echo", Some(4097), axum::body::Body::from(vec![0u8; 4097])),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            ("failed body", hop_request("POST", "/outbound/echo", None, failing_body()), StatusCode::BAD_REQUEST),
        ] {
            let (answered, _, body) = hop_call(hop_to(&stub, 4096), request).await;
            assert_eq!(answered, status, "{case}: {body}");
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(body["type"], "https://a2a-protocol.org/errors/proxy-error", "{case}");
            assert!(body.get("jsonrpc").is_none(), "{case}");
        }
    }

    /// A hop whose wait for the outbound listener times out after the body
    /// passed the cap answers 502, not 413; a send that fails on the body
    /// past the cap answers 413.
    #[tokio::test]
    async fn the_hop_reports_too_large_only_when_the_body_failed_the_send() {
        let stub = outbound_stub().await;
        let past_the_cap = || {
            axum::body::Body::from_stream(futures::stream::iter([Ok::<_, std::io::Error>(bytes::Bytes::from(
                vec![0u8; 4096 + 1024],
            ))]))
        };
        let stalling = Arc::new(SharedHostHop {
            target: stub.url.clone(),
            client: crate::http_client::shared_host_hop(std::time::Duration::from_millis(300)).unwrap(),
            forwarded_cert_header: "x-forwarded-client-cert".to_string(),
            max_body_bytes: 4096,
        });

        let (status, _, body) = hop_call(stalling, hop_request("POST", "/outbound/stall", None, past_the_cap())).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");

        let (status, _, body) = hop_call(
            hop_to(&stub, 4096),
            hop_request(
                "POST",
                "/outbound/echo",
                None,
                endless_counted_body(Arc::new(std::sync::atomic::AtomicUsize::new(0))),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    }

    /// The hop's refusals are logged with the caller's socket address, and
    /// never with the query.
    #[tokio::test]
    async fn the_hop_logs_its_refusals_with_the_callers_address() {
        let stub = outbound_stub().await;
        let caller: SocketAddr = "192.0.2.7:40123"
            .parse()
            .unwrap();
        let with_caller = |mut request: axum::extract::Request| {
            request
                .extensions_mut()
                .insert(axum::extract::ConnectInfo(caller));
            request
        };
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();

        hop_call(
            hop_to(&stub, 4096),
            with_caller(hop_request(
                "POST",
                "/outbound/echo?secret=query",
                Some(4097),
                axum::body::Body::from(vec![0u8; 4097]),
            )),
        )
        .await;
        hop_call(
            hop_to(&stub, 4096),
            with_caller(hop_request(
                "POST",
                "/outbound/echo?secret=query",
                None,
                endless_counted_body(Arc::new(std::sync::atomic::AtomicUsize::new(0))),
            )),
        )
        .await;

        let text = logs.text();
        assert_eq!(
            text.matches("caller=192.0.2.7:40123")
                .count(),
            2,
            "{text}"
        );
        assert!(text.contains("refused a declared oversize body"), "{text}");
        assert!(text.contains("refused an oversize body"), "{text}");
        assert!(!text.contains("secret"), "{text}");
    }

    #[tokio::test]
    async fn the_hop_refuses_a_declared_oversize_body_without_reading_it() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let stub = outbound_stub().await;
        let pulled = Arc::new(AtomicUsize::new(0));

        let (status, _, body) = hop_call(
            hop_to(&stub, 4096),
            hop_request("POST", "/outbound/echo", Some(4097), endless_counted_body(pulled.clone())),
        )
        .await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
        assert!(body.contains("Request body too large (max: 4096)"), "{body}");
        assert_eq!(pulled.load(Ordering::SeqCst), 0);
        assert_eq!(
            stub.started
                .load(Ordering::SeqCst),
            0,
            "the outbound listener was called"
        );

        let (status, _, body) = hop_call(
            hop_to(&stub, 4096),
            hop_request("POST", "/outbound/echo", Some(4096), axum::body::Body::from(vec![0u8; 4096])),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body, "POST 4096");
    }

    #[tokio::test]
    async fn the_hop_cuts_an_endless_body_at_the_limit() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let stub = outbound_stub().await;
        let pulled = Arc::new(AtomicUsize::new(0));
        let limit = 64 * 1024;

        let (status, _, body) = hop_call(
            hop_to(&stub, limit),
            hop_request("POST", "/outbound/echo", None, endless_counted_body(pulled.clone())),
        )
        .await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
        assert!(body.contains("Request body too large"), "{body}");
        let pulled = pulled.load(Ordering::SeqCst);
        assert!(pulled <= limit + SHARED_HOST_HOP_STREAM_MARGIN + HOP_CHUNK, "pulled {pulled} bytes");
        assert_eq!(
            stub.completed
                .load(Ordering::SeqCst),
            0,
            "a truncated body was delivered"
        );
    }

    #[tokio::test]
    async fn the_hop_stops_pulling_an_endless_body_the_outbound_listener_refuses() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let stub = outbound_stub().await;
        let pulled = Arc::new(AtomicUsize::new(0));
        let limit = 10 * 1024 * 1024;

        let (status, _, body) = hop_call(
            hop_to(&stub, limit),
            hop_request("POST", "/outbound/deny", None, endless_counted_body(pulled.clone())),
        )
        .await;
        // The listener closes on the unread body, and the reset can reach the
        // hop before its 401 does.
        assert!([StatusCode::UNAUTHORIZED, StatusCode::BAD_GATEWAY].contains(&status), "{status}: {body}");

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let settled = pulled.load(Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(pulled.load(Ordering::SeqCst), settled, "the hop kept pulling the refused body");
        assert!(
            settled <= limit / 2,
            "pulled {settled} bytes of a body the listener refused; only socket and transport buffers, well under the {limit}-byte cap, should be read"
        );
    }

    #[tokio::test]
    async fn the_hop_refuses_a_body_the_caller_fails_to_send_instead_of_forwarding_it_empty() {
        use std::sync::atomic::Ordering;
        let stub = outbound_stub().await;
        let failing = axum::body::Body::from_stream(futures::stream::iter([
            Ok(bytes::Bytes::from_static(b"{\"jsonrpc\":")),
            Err(std::io::Error::other("caller reset the stream")),
        ]));

        let (status, _, body) =
            hop_call(hop_to(&stub, 4096), hop_request("POST", "/outbound/echo", None, failing)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("Failed to read request body"), "{body}");
        assert_eq!(
            stub.completed
                .load(Ordering::SeqCst),
            0,
            "a body was delivered"
        );
    }

    #[tokio::test]
    async fn the_hop_passes_the_method_status_headers_and_body_through() {
        let stub = outbound_stub().await;

        for (method, body, expected) in [
            ("PATCH", axum::body::Body::from("abc"), "PATCH 3"),
            ("DELETE", axum::body::Body::from("abcd"), "DELETE 4"),
            ("GET", axum::body::Body::empty(), "GET 0"),
        ] {
            let (status, headers, answer) =
                hop_call(hop_to(&stub, 4096), hop_request(method, "/outbound/echo", None, body)).await;
            assert_eq!(status, StatusCode::CREATED, "{method}: {answer}");
            assert_eq!(headers.get("x-stub").unwrap(), "echo", "{method}");
            assert_eq!(answer, expected);
        }
    }

    #[tokio::test]
    async fn the_hop_streams_the_response_before_the_outbound_listener_ends_it() {
        let stub = outbound_stub().await;

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            forward_shared_host_hop(
                hop_to(&stub, 4096),
                hop_request("GET", "/outbound/stream", None, axum::body::Body::empty()),
            ),
        )
        .await
        .expect("the hop must answer before the stream ends");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        let mut body = response
            .into_body()
            .into_data_stream();
        let first = tokio::time::timeout(std::time::Duration::from_secs(10), body.next())
            .await
            .expect("the first event must arrive while the stream is open")
            .unwrap()
            .unwrap();
        assert_eq!(&first[..], b"data: first\n\n");
    }
}
