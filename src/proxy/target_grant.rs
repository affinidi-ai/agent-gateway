//! The Access Point Target's grant by binding.
//!
//! A surface whose `outbound_credentials` hold a `consent_mode: external`
//! binding sends its Target a grant the vault keeps under the hop
//! [`ACCESS_POINT_TARGET_HOP`]: the owner's, or the identified caller's, in a
//! header, in place of any credential of the caller's. The request goes only
//! to the origin of the provider's `resource`, through Strict egress pinned to
//! the vetted addresses, and the destination is checked again on every
//! request. A caller the Access Point did not identify is refused, so it never
//! acts as the owner or as another caller. A grant due a refresh is refreshed
//! first; a vendor's `401` that rejects the token gets one refresh and one
//! retry, and a `403` for a missing scope is answered `scope_insufficient`.
//! What cannot be released is refused before anything is sent, with a fixed
//! reason, in the Access Point's protocol: a JSON-RPC error on MCP, a problem
//! JSON otherwise.

use axum::http::StatusCode;
use axum::response::Response;
use tracing::warn;

use crate::config::agent_surface::{AgentSurface, GrantSubject, SurfaceProtocol};
use crate::config::types::{CredentialInjection, OutboundCredentialBinding};
use crate::credential_providers::CredentialProvider;
use crate::delegation_vault::grants::{ACCESS_POINT_TARGET_HOP, DelegatedGrant, GrantKey};
use crate::delegation_vault::release::{GrantRefusal, ReleaseContext};
use crate::state::ProxyState;

/// The request to the Access Point Target a grant may be sent with.
pub(crate) struct TargetRequest<'a> {
    pub method: &'a str,
    /// The request path after the Access Point's route.
    pub path: &'a str,
    pub headers: &'a axum::http::HeaderMap,
    /// A `2026-07-28` MCP request.
    pub modern: bool,
    pub body: &'a [u8],
    /// What a refusal's `request_rejected` record names.
    pub facts: &'a crate::audit::request_events::RequestFacts<'a>,
}

/// Where a request carrying the Target's grant goes: its binding, its
/// provider, the URL it is sent to, and the Strict client pinned to the
/// provider's resource.
pub(crate) struct TargetGrantRoute {
    binding: OutboundCredentialBinding,
    subject: GrantSubject,
    provider: CredentialProvider,
    target_url: String,
    client: reqwest::Client,
    mcp: bool,
}

/// The methods a request carrying the grant may have: MCP's Streamable HTTP
/// sends every message as a `POST`; A2A's bindings read with `GET` and remove
/// a push notification configuration with `DELETE`.
fn methods_with_the_grant(mcp: bool) -> &'static [&'static str] {
    if mcp {
        &["POST"]
    } else {
        &["GET", "POST", "DELETE"]
    }
}

/// The segments of `path`, the request path after the Access Point's route,
/// when the vendor reads it under the Target's endpoint path just as the
/// gateway does; `None` for one that could climb out of it or be read
/// another way. Each segment is decoded first, and is then non-empty, all
/// ASCII, so neither an overlong form (`%c0%ae`) nor a character a server
/// normalises to a dot (a fullwidth `%ef%bc%8e`), not made only of dots and
/// spaces, which servers that trim them read as `.` or `..` (`..%20`, `...`),
/// and holds no separator (`/`, `\`), `?`, `#`, `;`, `%` (a second encoding)
/// or control character.
fn forwarded_segments(path: &str) -> Option<Vec<&str>> {
    let tail = path.strip_prefix('/')?;
    if tail.is_empty() {
        return Some(Vec::new());
    }
    tail.split('/')
        .map(|segment| {
            let decoded = urlencoding::decode_binary(segment.as_bytes());
            let readable = decoded.is_ascii()
                && !decoded
                    .iter()
                    .all(|byte| matches!(byte, b'.' | b' '))
                && !decoded
                    .iter()
                    .any(|byte| b"/\\?#;%".contains(byte) || byte.is_ascii_control());
            readable.then_some(segment)
        })
        .collect()
}

/// Whether `surface`'s Target would be sent the grant on every path of its
/// origin: on A2A and AP2 the grant goes at or under the endpoint path, so an
/// endpoint at the root of its origin, `/` or no path, is refused. The A2A
/// operation paths (`/tasks`, `/v1/...`) are ones a vendor's other APIs use
/// too, so no list of them keeps the grant to the agent there. On MCP the
/// grant goes to the endpoint path alone.
pub(crate) fn sends_the_grant_across_the_origin(surface: &AgentSurface) -> bool {
    surface.access_point.protocol != SurfaceProtocol::Mcp
        && url::Url::parse(&surface.target.endpoint).is_ok_and(|endpoint| {
            endpoint
                .path()
                .trim_matches('/')
                .is_empty()
        })
}

/// The URL a request carrying the grant is sent to: the Target's endpoint,
/// its path followed by `segments`, and never the caller's query string.
fn forwarded_url(
    endpoint: &str,
    segments: &[&str],
) -> Option<String> {
    let mut url = url::Url::parse(endpoint).ok()?;
    let mut path = url
        .path()
        .trim_end_matches('/')
        .to_string();
    for segment in segments {
        path.push('/');
        path.push_str(segment);
    }
    url.set_path(&path);
    url.set_fragment(None);
    Some(url.into())
}

/// The `400` answer to a request whose path is not at or under the Target's
/// endpoint path as a request carrying the grant must be.
fn path_refused(
    mcp: bool,
    body: &[u8],
) -> Response {
    const MESSAGE: &str = "The request path is not one the Access Point's Target is sent";
    let mut response = if mcp {
        crate::mcp::request_validation::McpRequestValidationError {
            status: StatusCode::BAD_REQUEST,
            id: Some(mcp_request_id(body)),
            code: crate::mcp::errors::error_codes::INVALID_REQUEST,
            message: MESSAGE.to_string(),
            data: None,
        }
        .into_response()
    } else {
        crate::a2a::create_error_response(StatusCode::BAD_REQUEST, MESSAGE)
    };
    response
        .headers_mut()
        .insert(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    response
}

/// The `405` answer to a request whose method is not one the grant is sent
/// with, naming those that are.
fn method_refused(mcp: bool) -> Response {
    let mut response = crate::a2a::create_error_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "The request method is not one the Access Point's Target is sent",
    );
    let headers = response.headers_mut();
    if let Ok(allow) = axum::http::HeaderValue::from_str(&methods_with_the_grant(mcp).join(", ")) {
        headers.insert(axum::http::header::ALLOW, allow);
    }
    headers.insert(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    response
}

/// Log why the request was refused before anything was sent.
fn log_refusal(
    surface: &AgentSurface,
    reason: &'static str,
) {
    warn!(
        target: "credential_delegation",
        surface_id = %surface.surface_id,
        surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
        reason,
        "A request to an Access Point whose Target is bound by external consent was refused"
    );
}

/// The grant a request to the Target carries, with the headers it is sent in
/// and the caller it was released for.
pub(crate) struct ReleasedTargetGrant {
    grant: DelegatedGrant,
    key: GrantKey,
    headers: reqwest::header::HeaderMap,
    /// The identity hash of the caller the grant was released for, the one
    /// every injection of it, or of its refreshed token, is audited under.
    principal: String,
    caller: Option<crate::delegation_vault::audit::AuditCallerContext>,
}

/// Whether `surface`'s Target is bound by external consent: the vendor's
/// cookies and authentication challenges never reach its callers, whose
/// credentials the grant replaces.
pub(crate) fn binds_the_target(surface: &AgentSurface) -> bool {
    surface
        .target_external_credentials()
        .is_some()
}

/// Remove the Target's answer headers a caller of a Target bound by external
/// consent never receives: its cookies, and its authentication challenges,
/// which would have the caller authenticate with the vendor itself.
pub(crate) fn withhold_vendor_headers(response: &mut reqwest::Response) {
    let headers = response.headers_mut();
    headers.remove(reqwest::header::SET_COOKIE);
    headers.remove(reqwest::header::WWW_AUTHENTICATE);
}

/// Why the callers of a surface's Access Point are never released a grant by
/// binding: they are not authenticated by something the gateway can check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UncheckedCallers {
    /// DID Auth without `allowed_dids` accepts any DID that signs its
    /// challenge, so whoever mints one is a caller.
    SelfNamed,
    /// A JWT bearer method without `audiences`, on an Access Point that
    /// publishes no protected resource, accepts a token its issuer minted for
    /// any other service, so whoever holds one is a caller.
    AnyAudience,
    /// The gateway's own resource access tokens (`mcp_http.authorization`)
    /// name a caller by the subject its sign-in stated, under the gateway's
    /// issuer, not the identity provider's: callers of two identity providers
    /// with the same subject would share a caller's grant.
    NamedWithoutTheirIssuer,
}

impl UncheckedCallers {
    /// The fixed reason a request is refused for, in the log.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::SelfNamed => "callers_name_themselves",
            Self::AnyAudience => "callers_tokens_for_any_audience",
            Self::NamedWithoutTheirIssuer => "callers_named_without_their_issuer",
        }
    }

    /// Why a save of such a binding is refused.
    pub(crate) fn refusal(self) -> &'static str {
        match self {
            Self::SelfNamed => {
                "consent_mode external needs callers authenticated by something the gateway can check: the Access \
                 Point's did_auth accepts any DID that signs its challenge; list the DIDs it accepts in allowed_dids"
            }
            Self::AnyAudience => {
                "consent_mode external needs callers authenticated by something the gateway can check: the Access \
                 Point's jwt_bearer has no audiences, so it accepts a token its issuer minted for any other service; \
                 list the audiences it accepts, or publish caller_authentication.protected_resource"
            }
            Self::NamedWithoutTheirIssuer => {
                "consent_mode external with subject caller needs callers named with the issuer that named them: the \
                 gateway's resource access tokens (mcp_http.authorization) name a caller by its subject alone, so \
                 callers of two identity providers with the same subject would share a grant; use subject owner"
            }
        }
    }
}

/// Why the callers of `surface`'s Access Point are never released a grant by
/// binding for `subject`, or `None` when they may be.
pub(crate) fn unchecked_callers(
    surface: &AgentSurface,
    subject: GrantSubject,
) -> Option<UncheckedCallers> {
    if surface.admits_self_named_callers() {
        return Some(UncheckedCallers::SelfNamed);
    }
    if surface.admits_tokens_for_any_audience() {
        return Some(UncheckedCallers::AnyAudience);
    }
    let resource_tokens = surface
        .mcp_http
        .as_ref()
        .is_some_and(|http| http.authorization.is_some());
    (subject == GrantSubject::Caller && resource_tokens).then_some(UncheckedCallers::NamedWithoutTheirIssuer)
}

/// The caller's headers a Target bound by external consent is sent: the
/// protocol headers its requests need, `Content-Type` and `Accept`, MCP's
/// protocol version and session, and A2A's version and extensions, in their
/// 1.0 and 0.3 names. The gateway answers the MCP notification stream itself,
/// so `Last-Event-ID`, which resumes one, is not among them.
const PROTOCOL_HEADERS: [&str; 7] = [
    "content-type",
    "accept",
    "mcp-protocol-version",
    "mcp-session-id",
    "a2a-version",
    "a2a-extensions",
    "x-a2a-extensions",
];

/// Whether the caller's header `name` goes on to a Target bound by external
/// consent: only one of [`PROTOCOL_HEADERS`], and of those only what a Transit
/// Point sends its vendor
/// ([`crate::proxy::outbound_handler::should_forward_outbound_request_header`]),
/// never the header the caller's credential came in. Every other header the
/// caller set stays behind: its cookies and credentials, a caller-info, DID,
/// forwarding, path or method override header a vendor might read as another
/// principal, host, path or method, and its trace id, beside the gateway's.
pub(crate) fn forwards_caller_header(
    name: &str,
    source_auth_header: Option<&str>,
    header_metadata_mapping: Option<&crate::config::header_metadata_mapping::HeaderMetadataMappingConfig>,
) -> bool {
    PROTOCOL_HEADERS
        .iter()
        .any(|protocol| name.eq_ignore_ascii_case(protocol))
        && crate::proxy::outbound_handler::should_forward_outbound_request_header(name, header_metadata_mapping)
        && source_auth_header.is_none_or(|header| !name.eq_ignore_ascii_case(header))
}

/// The refusal of a request about to reach a Target bound by external consent
/// without its grant, as no request but a public discovery read may:
/// `connector_unavailable`.
pub(crate) fn refuse_without_the_grant(
    surface: &AgentSurface,
    body: &[u8],
) -> Response {
    let mcp = surface.access_point.protocol == SurfaceProtocol::Mcp;
    unavailable(surface, mcp, body, "request_without_the_grant")
}

/// The refusal of an answer the Target compressed although the gateway asked
/// for none, or `None` for an answer it can read: the gateway does not
/// decompress, so tool gating and the response checks would read none of it.
pub(crate) fn refuse_a_compressed_answer(
    surface: &AgentSurface,
    answer: &reqwest::header::HeaderMap,
    body: &[u8],
) -> Option<Response> {
    if !crate::proxy::upstream_body::is_compressed(answer) {
        return None;
    }
    let mcp = surface.access_point.protocol == SurfaceProtocol::Mcp;
    Some(unavailable(surface, mcp, body, "compressed_answer"))
}

/// The JSON-RPC id of an MCP request, for a refusal; `null` when it has none.
fn mcp_request_id(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|body| body.get("id").cloned())
        .unwrap_or(serde_json::Value::Null)
}

/// Refuse the request with `refusal`, logging why.
fn refuse(
    surface: &AgentSurface,
    mcp: bool,
    body: &[u8],
    refusal: &GrantRefusal,
    reason: &'static str,
) -> Response {
    warn!(
        target: "credential_delegation",
        surface_id = %surface.surface_id,
        surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
        reason,
        refusal = refusal.reason(),
        "The Access Point Target's grant by binding cannot be released - refusing the request"
    );
    refusal.response(mcp.then(|| mcp_request_id(body)))
}

/// Refuse the request for a reason a new connect would not fix:
/// `connector_unavailable`.
fn unavailable(
    surface: &AgentSurface,
    mcp: bool,
    body: &[u8],
    reason: &'static str,
) -> Response {
    refuse(surface, mcp, body, &GrantRefusal::ConnectorUnavailable, reason)
}

/// The route of a request to `surface`'s Target when the Target is bound by
/// external consent, or `None` when it is not, when the request is a public
/// discovery read, which carries no caller and so no grant, or when it is an
/// MCP `GET` for the notification stream or a `DELETE` ending a session, which
/// the gateway answers itself. Every request's path must be read the same way
/// by the gateway and the vendor ([`forwarded_segments`]), else it is refused
/// `400`. A request carrying the grant goes to the Target's endpoint path on
/// MCP, at or under it on A2A, without the caller's query string, and with a
/// method the protocol sends it with ([`methods_with_the_grant`]), else it is
/// refused `400` or `405`. The binding must be the only one, on a surface
/// without Transit Points, sending the grant in a header and in place of
/// every other credential; its provider must have an issuer and the surface's
/// tenant, and be permitted by the operator; and the URL must be a public
/// `https` URL with the origin of the provider's resource. A `2026-07-28` MCP
/// request is refused: such a binding's vendor is reached over a session
/// revision. Anything else is refused `connector_unavailable`, before the
/// vault is read. Every refusal is audited `request_rejected` at admission,
/// with a fixed reason.
pub(crate) async fn route(
    state: &ProxyState,
    request: TargetRequest<'_>,
) -> Result<Option<TargetGrantRoute>, Response> {
    use crate::audit::request_events::{RejectionReason, RejectionStage, request_rejected};
    use crate::mcp::errors::error_codes;
    let facts = request.facts;
    let modern = request.modern;
    let mcp = state
        .surface
        .access_point
        .protocol
        == SurfaceProtocol::Mcp;
    route_unaudited(state, request)
        .await
        .inspect_err(|refused| {
            // Every refusal of `route_unaudited` is one of these, by its
            // status: the `-32022` of a 2026-07-28 request and a path
            // refused are its only `400`s, a method refused its only `405`,
            // and every other is `connector_unavailable`.
            let status = refused.status();
            let (reason, rpc_error_code) = match status {
                StatusCode::BAD_REQUEST if modern => {
                    (RejectionReason::VersionUnsupported, Some(error_codes::UNSUPPORTED_PROTOCOL_VERSION))
                }
                StatusCode::BAD_REQUEST => {
                    (RejectionReason::TargetPathRefused, mcp.then_some(error_codes::INVALID_REQUEST))
                }
                StatusCode::METHOD_NOT_ALLOWED => (RejectionReason::TargetMethodRefused, None),
                _ => (RejectionReason::ConnectorUnavailable, mcp.then_some(error_codes::INTERNAL_ERROR)),
            };
            request_rejected(facts, RejectionStage::Admission, reason, status.as_u16(), rpc_error_code.map(i64::from));
        })
}

/// [`route`], without its audit.
async fn route_unaudited(
    state: &ProxyState,
    request: TargetRequest<'_>,
) -> Result<Option<TargetGrantRoute>, Response> {
    let surface = &state.surface;
    let Some(binding) = surface.target_external_credentials() else {
        return Ok(None);
    };
    let mcp = surface.access_point.protocol == SurfaceProtocol::Mcp;
    let body = request.body;
    if request.modern {
        warn!(
            target: "credential_delegation",
            surface_id = %surface.surface_id,
            surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
            "A 2026-07-28 MCP request was sent to an Access Point whose Target is bound by external consent - \
             refusing the request"
        );
        return Err(unsupported_modern_request(body));
    }
    let Some(segments) = forwarded_segments(request.path) else {
        log_refusal(surface, "path_not_read_alike");
        return Err(path_refused(mcp, body));
    };
    if crate::proxy::paths::is_public_request(request.method, request.path) {
        return Ok(None);
    }
    if mcp && !segments.is_empty() {
        log_refusal(surface, "path_not_the_endpoint");
        return Err(path_refused(mcp, body));
    }
    if mcp
        && ((request.method == "GET" && crate::mcp::sse_server::client_wants_sse(request.headers))
            || request.method == "DELETE")
    {
        return Ok(None);
    }
    if !methods_with_the_grant(mcp).contains(&request.method) {
        log_refusal(surface, "method_not_sent_the_grant");
        return Err(method_refused(mcp));
    }
    let Some(target_url) = forwarded_url(&surface.target.endpoint, &segments) else {
        return Err(unavailable(surface, mcp, body, "target_not_a_url"));
    };
    if sends_the_grant_across_the_origin(surface) {
        return Err(unavailable(surface, mcp, body, "target_at_the_origin_root"));
    }
    let Some(subject) = binding.subject else {
        return Err(unavailable(surface, mcp, body, "no_subject"));
    };
    if let Some(unchecked) = unchecked_callers(surface, subject) {
        return Err(unavailable(surface, mcp, body, unchecked.reason()));
    }
    if surface.presents_the_agent_to_the_target() {
        return Err(unavailable(surface, mcp, body, "presentation_of_the_agent"));
    }
    if surface.charges_callers() {
        return Err(unavailable(surface, mcp, body, "callers_charged"));
    }
    if surface
        .outbound_credentials
        .len()
        != 1
    {
        return Err(unavailable(surface, mcp, body, "other_outbound_credentials"));
    }
    if !surface
        .transit_points()
        .is_empty()
    {
        return Err(unavailable(surface, mcp, body, "surface_with_transit_points"));
    }
    if matches!(binding.inject_as, CredentialInjection::Meta { .. }) {
        return Err(unavailable(surface, mcp, body, "grant_injected_into_the_body"));
    }
    if surface
        .target_auth()
        .is_some()
    {
        return Err(unavailable(surface, mcp, body, "target_auth_beside_the_grant"));
    }
    if surface
        .source_auth()
        .is_some_and(
            |auth| matches!(auth, crate::source_auth::SourceAuthConfig::JwtBearer(config) if config.forward_header),
        )
    {
        return Err(unavailable(surface, mcp, body, "caller_credential_forwarded"));
    }
    let (Some(_), Some(providers)) = (&state.delegation_vault_store, &state.credential_provider_store) else {
        return Err(unavailable(surface, mcp, body, "stores_unavailable"));
    };
    let provider = match providers
        .get(&binding.credential_provider_id)
        .await
    {
        Ok(Some(provider)) => provider,
        Ok(None) | Err(_) => return Err(unavailable(surface, mcp, body, "provider_unavailable")),
    };
    if !provider.is_external_consent() {
        return Err(unavailable(surface, mcp, body, "provider_without_issuer"));
    }
    if provider.tenant_id != surface.tenant_id {
        return Err(unavailable(surface, mcp, body, "provider_of_another_tenant"));
    }
    let allowlist = state
        .egress_allowlist
        .as_deref();
    if crate::credential_providers::external::check_grant_destination(&provider, &target_url, allowlist)
        .await
        .is_err()
    {
        return Err(unavailable(surface, mcp, body, "destination_not_the_resource"));
    }
    if !crate::credential_providers::external::resource_permitted(
        &provider,
        &state
            .network_config
            .external_consent_resource_origins,
    ) {
        return Err(unavailable(surface, mcp, body, "resource_not_permitted_for_issuer"));
    }
    if crate::credential_providers::external::issuer_permitted(
        &provider,
        state
            .network_config
            .external_consent_issuers
            .as_ref(),
    )
    .is_err()
    {
        return Err(unavailable(surface, mcp, body, "issuer_not_permitted"));
    }
    let timeout = std::time::Duration::from_secs(
        state
            .config
            .a2a
            .timeout_seconds,
    );
    let client = crate::egress::pinned_vendor_client(&target_url, timeout, allowlist)
        .await
        .map_err(|error| {
            warn!(
                target: "credential_delegation",
                surface_id = %surface.surface_id,
                error = ?error.to_string(),
                "The Target of a request carrying a grant by binding was refused by Strict egress"
            );
            unavailable(surface, mcp, body, "forward_refused_by_strict_egress")
        })?;
    Ok(Some(TargetGrantRoute {
        binding: binding.clone(),
        subject,
        provider,
        target_url,
        client,
        mcp,
    }))
}

/// The `-32022` answer to a `2026-07-28` MCP request.
fn unsupported_modern_request(body: &[u8]) -> Response {
    let id = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|body| body.get("id").cloned());
    crate::mcp::request_validation::McpRequestValidationError {
        status: StatusCode::BAD_REQUEST,
        id,
        code: crate::mcp::errors::error_codes::UNSUPPORTED_PROTOCOL_VERSION,
        message: "Unsupported protocol version".into(),
        data: Some(serde_json::json!({
            "requested": crate::mcp::MCP_MODERN_VERSION,
            "supported": [crate::mcp::MCP_LEGACY_VERSION],
        })),
    }
    .into_response()
}

/// The answer to a request whose caller the Access Point did not identify:
/// `403`, as a JSON-RPC error (`-32001`) on MCP and a problem JSON otherwise.
fn caller_not_identified(
    mcp: bool,
    body: &[u8],
) -> Response {
    use axum::response::IntoResponse as _;
    const MESSAGE: &str = "Delegated credentials need the caller's identity, and this request does not establish one";
    let mut response = if mcp {
        crate::mcp::request_validation::McpRequestValidationError {
            status: StatusCode::FORBIDDEN,
            id: Some(mcp_request_id(body)),
            code: -32001,
            message: MESSAGE.to_string(),
            data: None,
        }
        .into_response()
    } else {
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(axum::http::header::CONTENT_TYPE, "application/problem+json")
            .body(axum::body::Body::from(
                serde_json::json!({
                    "type": "https://affinidi.com/atg/errors/identity-required",
                    "title": "Identity Required for Credential Delegation",
                    "status": 403,
                    "detail": MESSAGE,
                })
                .to_string(),
            ))
            .unwrap_or_else(|_| StatusCode::FORBIDDEN.into_response())
    };
    response
        .headers_mut()
        .insert(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    response
}

/// The answer to a request that arrived over Fabric for a surface whose Target
/// is bound by external consent, or `None` to let it through. Its caller is
/// the one the peer gateway asserts, which never keys a grant, so it is
/// refused as a request whose caller the gateway did not identify. A public
/// discovery read is refused too: it would carry the peer's headers, its
/// caller's cookies among them, to the vendor, and no request over Fabric can
/// use such a Target, so nothing needs its discovery there. Any request to a
/// Target that is not bound by external consent passes.
pub(crate) fn refuse_over_fabric(
    surface: &AgentSurface,
    body: &[u8],
) -> Option<Response> {
    if !binds_the_target(surface) {
        return None;
    }
    warn!(
        target: "credential_delegation",
        surface_id = %surface.surface_id,
        reason = "over_fabric",
        "The Access Point Target's grant by binding is not released for a request that arrived over Fabric - \
         refusing the request"
    );
    Some(caller_not_identified(surface.access_point.protocol == SurfaceProtocol::Mcp, body))
}

/// What releasing the Target's grant for one caller needs.
pub(crate) struct Caller<'a> {
    pub identity: Option<&'a crate::source_auth::AuthenticatedIdentity>,
    /// The caller's source authentication failed, and policy let the request
    /// on.
    pub source_auth_failed: bool,
    pub facts: &'a crate::audit::request_events::RequestFacts<'a>,
}

impl TargetGrantRoute {
    /// The Strict client pinned to the provider's resource, which every
    /// request on this route is sent with.
    pub(crate) fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// The URL every request on this route is sent to.
    pub(crate) fn target_url(&self) -> &str {
        &self.target_url
    }

    fn release_context<'a>(
        &self,
        state: &'a ProxyState,
    ) -> Option<ReleaseContext<'a>> {
        Some(ReleaseContext {
            vault: state
                .delegation_vault_store
                .as_ref()?,
            secrets: state.secrets_store.as_ref(),
            exact_allowlist: state
                .egress_allowlist
                .as_deref(),
            refusal_limit: crate::delegation_vault::release::refusal_limit(
                state
                    .network_config
                    .external_consent_refresh_refusals,
            ),
        })
    }

    /// Release the grant for `caller`: the owner's to any caller the Access
    /// Point identified, a caller's to that caller only, by its identity hash.
    /// A caller the Access Point did not identify is refused, and so is a
    /// grant asked for beyond its binding's scopes as saved now.
    pub(crate) async fn release(
        &self,
        state: &ProxyState,
        caller: Caller<'_>,
        body: &[u8],
    ) -> Result<ReleasedTargetGrant, Response> {
        let surface = &state.surface;
        let principal = (!caller.source_auth_failed)
            .then(|| crate::proxy::handler::source_auth_user_hash(caller.identity, surface))
            .flatten();
        let Some(principal) = principal else {
            warn!(
                target: "credential_delegation",
                surface_id = %surface.surface_id,
                surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
                reason = "caller_not_identified",
                "The Access Point Target's grant by binding cannot be released - refusing the request"
            );
            crate::audit::request_events::request_rejected(
                caller.facts,
                crate::audit::request_events::RejectionStage::Admission,
                crate::audit::request_events::RejectionReason::ConsentIdentityRequired,
                403,
                None,
            );
            return Err(caller_not_identified(self.mcp, body));
        };
        let tenant = surface.tenant_id.as_deref();
        let key = match self.subject {
            GrantSubject::Owner => {
                GrantKey::owner(tenant, &surface.surface_id, ACCESS_POINT_TARGET_HOP, &self.provider.id)
            }
            GrantSubject::Caller => {
                match GrantKey::caller(
                    tenant,
                    &surface.surface_id,
                    ACCESS_POINT_TARGET_HOP,
                    &self.provider.id,
                    &principal,
                ) {
                    Some(key) => key,
                    None => return Err(unavailable(surface, self.mcp, body, "caller_without_identity_hash")),
                }
            }
        };
        let Some(release) = self.release_context(state) else {
            return Err(unavailable(surface, self.mcp, body, "stores_unavailable"));
        };
        let grant = match release
            .release(&self.provider, &key, self.subject)
            .await
        {
            Ok(grant) => grant,
            Err(refused) => return Err(refuse(surface, self.mcp, body, &refused.refusal, refused.reason)),
        };
        // Within the binding serving this call, and within every place the
        // surface serves the Target's binding, as storing a grant and the
        // sweep decide.
        if !crate::identity::handlers::surface_grants::binding_permits(
            &self.binding.scopes,
            &self.provider.default_scopes,
            &grant,
        ) || !crate::identity::handlers::surface_grants::serves_grant(
            &state.served_surface,
            &grant,
            &self.provider.default_scopes,
        ) {
            return Err(refuse(
                surface,
                self.mcp,
                body,
                &GrantRefusal::connect_required(&key, self.subject),
                "grant_beyond_the_bindings_scopes",
            ));
        }
        let headers = self
            .headers_for(&grant)
            .ok_or_else(|| unavailable(surface, self.mcp, body, "grant_not_a_header_value"))?;
        let released = ReleasedTargetGrant {
            grant,
            key,
            headers,
            principal,
            caller: caller
                .identity
                .map(crate::delegation_vault::audit::build_caller_context),
        };
        self.injected(surface, &release, &released, &released.grant)
            .await;
        Ok(released)
    }

    /// Record that `grant` is injected into a request released for
    /// `released`'s caller: mark it used, and audit it under that caller's
    /// identity hash, whichever subject the binding has.
    async fn injected(
        &self,
        surface: &AgentSurface,
        release: &ReleaseContext<'_>,
        released: &ReleasedTargetGrant,
        grant: &DelegatedGrant,
    ) {
        if let Err(error) = release
            .vault
            .mark_grant_used(&grant.id)
            .await
        {
            tracing::debug!(
                target: "credential_delegation",
                surface_id = %surface.surface_id,
                error = %error,
                "Failed to record a grant's use"
            );
        }
        self.audit_injected(surface, &released.principal, released.caller.clone(), grant);
    }

    /// The headers `grant` is sent in, as the binding's `inject_as` says.
    fn headers_for(
        &self,
        grant: &DelegatedGrant,
    ) -> Option<reqwest::header::HeaderMap> {
        let mut headers = reqwest::header::HeaderMap::new();
        for injection in
            crate::proxy::credential_delegation::build_injection_headers(&self.binding.inject_as, &grant.access_token)
        {
            let crate::proxy::credential_delegation::ResolvedCredentialInjection::Header { name, value } = injection
            else {
                return None;
            };
            headers.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).ok()?,
                reqwest::header::HeaderValue::from_str(&value).ok()?,
            );
        }
        Some(headers)
    }

    /// Audit that the Target's grant was injected into a request.
    fn audit_injected(
        &self,
        surface: &AgentSurface,
        principal: &str,
        caller: Option<crate::delegation_vault::audit::AuditCallerContext>,
        grant: &DelegatedGrant,
    ) {
        crate::delegation_vault::audit::emit("token_injected", || {
            let mut event = crate::delegation_vault::audit::audit_event(
                crate::delegation_vault::audit::DelegationAuditAction::TokenInjected,
                None,
                Some(principal),
                Some(&self.provider.id),
                Some(&surface.surface_id),
            );
            event.token_id = Some(grant.id.clone());
            event.provider_name = Some(self.provider.name.clone());
            event.scopes = Some(grant.scopes.clone());
            event.channel_name = Some(surface.name.clone());
            event.detail = Some(
                match self.subject {
                    GrantSubject::Owner => "grant_by_binding:owner:target",
                    GrantSubject::Caller => "grant_by_binding:caller:target",
                }
                .to_string(),
            );
            event.caller = caller;
            event
        });
    }

    /// Answer the Target's response to a request that carried `released`, as a
    /// Transit Point answers its vendor's
    /// ([`crate::delegation_vault::release::vendor_answer`]): a `403` for a
    /// missing scope answers `scope_insufficient`; a `401` whose `Bearer`
    /// challenge rejects the token (`invalid_token`) gets one refresh,
    /// single-flight, and one retry of `retry`, the request as it was sent,
    /// with the new token, a target checking the token before it acts; a grant
    /// that cannot be refreshed, or whose refresh token is refused, is removed
    /// and revoked while it still holds the token refused, and answers
    /// `connect_required`. A second `401` refuses this request,
    /// `connector_unavailable`, and keeps the fresh grant. A `401` without
    /// such a challenge, a refresh that fails for a reason a new connect would
    /// not fix, and a body too large to send again (`retry` is `None`) keep
    /// the grant and answer `connector_unavailable`. Any other answer passes
    /// through.
    pub(crate) async fn answer(
        &self,
        state: &ProxyState,
        released: ReleasedTargetGrant,
        response: reqwest::Response,
        retry: Option<reqwest::RequestBuilder>,
        body: &[u8],
    ) -> Result<reqwest::Response, Response> {
        use crate::delegation_vault::release::{VendorAnswer, vendor_answer, vendor_answer_to_a_retry};
        let surface = &state.surface;
        match vendor_answer(response.status(), response.headers()) {
            VendorAnswer::Pass => return Ok(response),
            VendorAnswer::Refuse(refused) => {
                return Err(refuse(surface, self.mcp, body, &refused.refusal, refused.reason));
            }
            VendorAnswer::TokenRejected => drop(response),
        }
        let Some(release) = self.release_context(state) else {
            return Err(unavailable(surface, self.mcp, body, "stores_unavailable"));
        };
        let fresh = match release
            .retry_grant(&self.provider, &released.key, self.subject, &released.grant, retry.is_some())
            .await
        {
            Ok(fresh) => fresh,
            Err(refused) => return Err(refuse(surface, self.mcp, body, &refused.refusal, refused.reason)),
        };
        let Some(retry) = retry else {
            return Err(unavailable(
                surface,
                self.mcp,
                body,
                "vendor_refused_a_large_body_refreshed_for_the_next_call",
            ));
        };
        let Some(headers) = self.headers_for(&fresh) else {
            return Err(unavailable(surface, self.mcp, body, "grant_not_a_header_value"));
        };
        let (client, request) = retry.build_split();
        let Ok(mut request) = request else {
            return Err(unavailable(surface, self.mcp, body, "retry_not_rebuilt"));
        };
        for (name, value) in &headers {
            request
                .headers_mut()
                .insert(name, value.clone());
        }
        self.injected(surface, &release, &released, &fresh)
            .await;
        let retried = match client.execute(request).await {
            Ok(retried) => retried,
            Err(error) => {
                warn!(
                    target: "credential_delegation",
                    surface_id = %surface.surface_id,
                    error = %error.without_url(),
                    "The retry of a request whose grant the Target refused failed"
                );
                return Err(crate::a2a::create_error_response(StatusCode::BAD_GATEWAY, "Upstream request failed"));
            }
        };
        if let Err(refused) = vendor_answer_to_a_retry(retried.status(), retried.headers()) {
            drop(retried);
            return Err(refuse(surface, self.mcp, body, &refused.refusal, refused.reason));
        }
        Ok(retried)
    }
}

impl ReleasedTargetGrant {
    /// `request` with the grant's headers in place of any of the same name.
    pub(crate) fn apply(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, Box<Response>> {
        let (client, built) = request.build_split();
        let mut built = built.map_err(|_| {
            Box::new(crate::a2a::create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid upstream request"))
        })?;
        for (name, value) in &self.headers {
            built
                .headers_mut()
                .insert(name, value.clone());
        }
        Ok(reqwest::RequestBuilder::from_parts(client, built))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface(
        protocol: &str,
        outbound_credentials: serde_json::Value,
    ) -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": "vendor-agent", "name": "vendor-agent", "tenant_id": "tenant-a",
            "access_point": {"listen_address": "https://gateway.example", "route": "/vendor", "protocol": protocol},
            "target": {"endpoint": "https://mcp.vendor.example/mcp"},
            "outbound_credentials": outbound_credentials
        }))
        .unwrap()
    }

    async fn read(response: Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// A request that arrived over Fabric names its caller as the peer gateway
    /// asserts it, which never keys a grant: to a Target bound by external
    /// consent it is refused as a request whose caller the gateway did not
    /// identify, in the Access Point's protocol, and so is a public discovery
    /// read, which would carry the peer's headers to the vendor. Any other
    /// Target is let through.
    #[tokio::test]
    async fn a_request_over_fabric_never_gets_the_targets_grant() {
        let external = serde_json::json!([{"credential_provider_id": "vendor", "consent_mode": "external",
            "subject": "owner"}]);
        let call = br#"{"jsonrpc":"2.0","id":"call-1","method":"tools/list"}"#;
        let refused = refuse_over_fabric(&surface("mcp", external.clone()), call).expect("a Fabric caller is refused");
        let (status, body) = read(refused).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["id"], "call-1");
        assert_eq!(body["error"]["code"], -32001);
        let refused = refuse_over_fabric(&surface("a2a", external.clone()), call).expect("a Fabric caller is refused");
        let (status, body) = read(refused).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["type"], "https://affinidi.com/atg/errors/identity-required");
        let refused =
            refuse_over_fabric(&surface("a2a", external), b"").expect("a Fabric discovery read, without a body");
        assert_eq!(read(refused).await.0, StatusCode::FORBIDDEN);
        let agent_keyed = serde_json::json!([{"credential_provider_id": "agent-keyed"}]);
        assert!(refuse_over_fabric(&surface("mcp", agent_keyed), call).is_none());
    }

    /// A grant by binding is never released to callers the gateway cannot
    /// check: any caller of an Access Point whose DID Auth has no allow-list,
    /// and, for a caller's own grant, a caller of an Access Point that takes
    /// the gateway's resource access tokens, which name it without the issuer
    /// that named it.
    #[test]
    fn a_grant_is_released_only_to_callers_the_gateway_can_check() {
        let external = serde_json::json!([{"credential_provider_id": "vendor", "consent_mode": "external",
            "subject": "owner"}]);
        let with = |pointer: &str, value: serde_json::Value| {
            let mut surface = serde_json::to_value(surface("mcp", external.clone())).unwrap();
            let (parent, name) = pointer
                .rsplit_once('/')
                .unwrap();
            surface
                .pointer_mut(parent)
                .unwrap()[name] = value;
            serde_json::from_value::<AgentSurface>(surface).unwrap()
        };
        let did_auth = |allowed_dids: serde_json::Value| {
            with(
                "/access_point/caller_authentication",
                serde_json::json!({"methods": [{"type": "did_auth",
                    "extraction": {"source": "http_header", "field": "X-DID-Auth-Session"},
                    "allowed_dids": allowed_dids}]}),
            )
        };
        let resource_tokens = with(
            "/mcp_http",
            serde_json::json!({"authorization": {"resource": "https://gateway.example/vendor", "scopes": ["read"]}}),
        );
        let open = did_auth(serde_json::json!([]));
        let listed = did_auth(serde_json::json!(["did:example:alice"]));
        for subject in [GrantSubject::Owner, GrantSubject::Caller] {
            assert_eq!(unchecked_callers(&open, subject), Some(UncheckedCallers::SelfNamed), "{subject:?}");
            assert_eq!(unchecked_callers(&listed, subject), None, "{subject:?}");
            assert_eq!(unchecked_callers(&surface("mcp", external.clone()), subject), None, "{subject:?}");
        }
        assert_eq!(unchecked_callers(&resource_tokens, GrantSubject::Owner), None);
        assert_eq!(
            unchecked_callers(&resource_tokens, GrantSubject::Caller),
            Some(UncheckedCallers::NamedWithoutTheirIssuer)
        );
    }

    /// A JWT bearer method without `audiences`, on an Access Point that
    /// publishes no protected resource, which would bind the audience,
    /// accepts a token its issuer minted for any other service, so whoever
    /// holds one is a caller: no grant by binding is released to its callers,
    /// among any of the methods. With an audience, or a protected resource,
    /// they may be.
    #[test]
    fn a_grant_is_never_released_to_callers_with_tokens_for_any_audience() {
        let external = serde_json::json!([{"credential_provider_id": "vendor", "consent_mode": "external",
            "subject": "owner"}]);
        let authenticating = |methods: serde_json::Value, protected_resource: Option<serde_json::Value>| {
            let mut surface = serde_json::to_value(surface("mcp", external.clone())).unwrap();
            surface["access_point"]["caller_authentication"] = serde_json::json!({"methods": methods});
            if let Some(protected_resource) = protected_resource {
                surface["access_point"]["caller_authentication"]["protected_resource"] = protected_resource;
            }
            serde_json::from_value::<AgentSurface>(surface).unwrap()
        };
        let jwt = |audiences: serde_json::Value| {
            serde_json::json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "strategy-1",
                "audiences": audiences})
        };
        let api_key = serde_json::json!({"type": "api_key",
            "extraction": {"source": "http_header", "field": "X-API-Key"}, "secret_id": "caller-key"});
        let protected_resource = serde_json::json!({"resource": "https://gateway.example/vendor",
            "authorization_servers": ["https://issuer.example"]});

        for subject in [GrantSubject::Owner, GrantSubject::Caller] {
            for (case, methods) in [
                ("alone", serde_json::json!([jwt(serde_json::json!([]))])),
                ("second", serde_json::json!([api_key.clone(), jwt(serde_json::json!([]))])),
            ] {
                assert_eq!(
                    unchecked_callers(&authenticating(methods, None), subject),
                    Some(UncheckedCallers::AnyAudience),
                    "{subject:?}, {case}"
                );
            }
            let bound = authenticating(serde_json::json!([jwt(serde_json::json!(["https://gateway.example"]))]), None);
            assert_eq!(unchecked_callers(&bound, subject), None, "{subject:?}, an audience");
            let published =
                authenticating(serde_json::json!([jwt(serde_json::json!([]))]), Some(protected_resource.clone()));
            assert_eq!(unchecked_callers(&published, subject), None, "{subject:?}, a protected resource");
        }
    }
}
