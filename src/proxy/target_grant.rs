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

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::Response;
use tracing::warn;

use crate::config::agent_surface::{AgentSurface, GrantSubject, SurfaceProtocol};
use crate::config::types::{CredentialInjection, OutboundCredentialBinding};
use crate::credential_providers::CredentialProvider;
use crate::delegation_vault::grants::{ACCESS_POINT_TARGET_HOP, DelegatedGrant, GrantKey};
use crate::delegation_vault::release::{GrantRefusal, Refused, ReleaseContext};
use crate::state::ProxyState;

/// The request to the Access Point Target a grant may be sent with.
pub(crate) struct TargetRequest<'a> {
    pub method: &'a str,
    /// The request path after the Access Point's route.
    pub path: &'a str,
    /// The request's query string, which a request carrying the grant never
    /// has.
    pub query: Option<&'a str>,
    pub headers: &'a axum::http::HeaderMap,
    /// A `2026-07-28` MCP request.
    pub modern: bool,
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

/// The URL a request carrying the grant is sent to: the Target's endpoint and
/// its path followed by `segments`. Such a request has no query string.
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
/// endpoint path as a request carrying the grant must be, or that has a query
/// string, which such a request is never sent with.
fn path_refused(
    mcp: bool,
    body: &[u8],
) -> Response {
    const MESSAGE: &str = "The request path or query is not one the Access Point's Target is sent";
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
/// never a header a caller-authentication method reads. Every other header the
/// caller set stays behind: its cookies and credentials, a caller-info, DID,
/// forwarding, path or method override header a vendor might read as another
/// principal, host, path or method, and its trace id, beside the gateway's.
pub(crate) fn forwards_caller_header(
    name: &str,
    source_auth_headers: &[&str],
    header_metadata_mapping: Option<&crate::config::header_metadata_mapping::HeaderMetadataMappingConfig>,
) -> bool {
    PROTOCOL_HEADERS
        .iter()
        .any(|protocol| name.eq_ignore_ascii_case(protocol))
        && crate::proxy::outbound_handler::should_forward_outbound_request_header(name, header_metadata_mapping)
        && !source_auth_headers
            .iter()
            .any(|header| name.eq_ignore_ascii_case(header))
}

/// The refusal of a request about to reach a Target bound by external consent
/// without its grant, as no request but a public discovery read may:
/// `connector_unavailable`.
pub(crate) fn refuse_without_the_grant(
    surface: &AgentSurface,
    body: &[u8],
) -> Response {
    unavailable(surface, "request_without_the_grant").response(surface, body)
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
    Some(unavailable(surface, "compressed_answer").response(surface, body))
}

/// The JSON-RPC id of an MCP request, for a refusal; `null` when it has none.
fn mcp_request_id(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|body| body.get("id").cloned())
        .unwrap_or(serde_json::Value::Null)
}

/// Whether `surface`'s Access Point speaks MCP, which refuses with JSON-RPC
/// errors.
fn speaks_mcp(surface: &AgentSurface) -> bool {
    surface.access_point.protocol == SurfaceProtocol::Mcp
}

/// Refuse the request with `refused`, logging why.
fn refuse(
    surface: &AgentSurface,
    refused: Refused,
) -> TargetGrantRefusal {
    warn!(
        target: "credential_delegation",
        surface_id = %surface.surface_id,
        surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
        reason = refused.reason,
        refusal = refused.refusal.reason(),
        "The Access Point Target's grant by binding cannot be released - refusing the request"
    );
    TargetGrantRefusal::Grant(refused)
}

/// Refuse the request for a reason a new connect would not fix:
/// `connector_unavailable`.
fn unavailable(
    surface: &AgentSurface,
    reason: &'static str,
) -> TargetGrantRefusal {
    refuse(
        surface,
        Refused {
            refusal: GrantRefusal::ConnectorUnavailable,
            reason,
        },
    )
}

/// Why a request to a Target bound by external consent is refused. The
/// handler answers it in the Access Point's protocol ([`Self::response`]).
#[derive(Debug, thiserror::Error)]
pub(crate) enum TargetGrantRefusal {
    /// A `2026-07-28` MCP request: such a binding's vendor is reached over a
    /// session revision.
    #[error("a 2026-07-28 MCP request")]
    Version,
    /// A path or query the grant is not sent with ([`path_refused`]).
    #[error("a path or query the grant is not sent with")]
    Path,
    /// A method the grant is not sent with ([`method_refused`]).
    #[error("a method the grant is not sent with")]
    Method,
    /// A caller the Access Point did not identify ([`caller_not_identified`]).
    #[error("a caller the Access Point did not identify")]
    CallerNotIdentified,
    /// The grant cannot be released or used, with the reason it is logged with.
    #[error("{}", .0.reason)]
    Grant(Refused),
    /// The retry with a refreshed grant could not be sent.
    #[error("the retry with a refreshed grant could not be sent")]
    RetryNotSent,
    /// The request to the Target could not be built with the grant's headers.
    #[error("the request to the Target could not be built")]
    RequestNotBuilt,
}

impl TargetGrantRefusal {
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            Self::Version | Self::Path => StatusCode::BAD_REQUEST,
            Self::Method => StatusCode::METHOD_NOT_ALLOWED,
            Self::CallerNotIdentified => StatusCode::FORBIDDEN,
            Self::Grant(refused) => refused.refusal.status(),
            Self::RetryNotSent => StatusCode::BAD_GATEWAY,
            Self::RequestNotBuilt => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The JSON-RPC error code of the answer, when `mcp`, the Access Point
    /// speaking MCP, gives it one.
    fn rpc_error_code(
        &self,
        mcp: bool,
    ) -> Option<i32> {
        use crate::mcp::errors::error_codes;
        match self {
            Self::Version => Some(error_codes::UNSUPPORTED_PROTOCOL_VERSION),
            Self::Path => mcp.then_some(error_codes::INVALID_REQUEST),
            Self::Grant(Refused {
                refusal: GrantRefusal::ConnectorUnavailable,
                ..
            }) => mcp.then_some(error_codes::INTERNAL_ERROR),
            Self::CallerNotIdentified | Self::Grant(_) => mcp.then_some(-32001),
            Self::Method | Self::RetryNotSent | Self::RequestNotBuilt => None,
        }
    }

    /// The answer, in the protocol of `surface`'s Access Point: on MCP a
    /// JSON-RPC error for the id of `body`, the request's.
    pub(crate) fn response(
        &self,
        surface: &AgentSurface,
        body: &[u8],
    ) -> Response {
        let mcp = speaks_mcp(surface);
        match self {
            Self::Version => unsupported_modern_request(body),
            Self::Path => path_refused(mcp, body),
            Self::Method => method_refused(mcp),
            Self::CallerNotIdentified => caller_not_identified(mcp, body),
            Self::Grant(refused) => refused
                .refusal
                .response(mcp.then(|| mcp_request_id(body))),
            Self::RetryNotSent => crate::a2a::create_error_response(StatusCode::BAD_GATEWAY, "Upstream request failed"),
            Self::RequestNotBuilt => {
                crate::a2a::create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid upstream request")
            }
        }
    }
}

/// A rule of the Access Point Target's `consent_mode: external` binding that
/// a view of the surface breaks. A save is refused with [`Self::refusal`], and
/// a surface stored outside the API that breaks one answers
/// `connector_unavailable`, logged with [`Self::reason`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TargetBindingViolation {
    OtherBindings,
    TransitPoints,
    InjectedIntoTheBody,
    AtTheOriginRoot,
    TargetAuth,
    CallerCredentialForwarded,
    CallersCharged,
    PresentationOfTheAgent,
    CustomMetadata,
}

impl TargetBindingViolation {
    /// The fixed reason a request refused for it is logged with.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::OtherBindings => "other_outbound_credentials",
            Self::TransitPoints => "surface_with_transit_points",
            Self::InjectedIntoTheBody => "grant_injected_into_the_body",
            Self::AtTheOriginRoot => "target_at_the_origin_root",
            Self::TargetAuth => "target_auth_beside_the_grant",
            Self::CallerCredentialForwarded => "caller_credential_forwarded",
            Self::CallersCharged => "callers_charged",
            Self::PresentationOfTheAgent => "presentation_of_the_agent",
            Self::CustomMetadata => "custom_metadata_beside_the_grant",
        }
    }

    /// What a save that breaks it is refused with.
    pub(crate) fn refusal(self) -> &'static str {
        match self {
            Self::OtherBindings => {
                "consent_mode external binds the Access Point's Target alone: outbound_credentials can hold no \
                 other binding"
            }
            Self::TransitPoints => {
                "consent_mode external in outbound_credentials binds the Access Point's Target, on a surface \
                 without Transit Points: outbound_credentials apply on every Transit Point"
            }
            Self::InjectedIntoTheBody => {
                "consent_mode external injects the grant as a header: bearer_header or custom_header"
            }
            Self::AtTheOriginRoot => {
                "consent_mode external on an A2A or AP2 Access Point sends the grant at or under the Target's \
                 endpoint path, so target.endpoint cannot be the root of its origin, where that is every path \
                 of the vendor's: give it the agent's own path"
            }
            Self::TargetAuth => {
                "consent_mode external sends the grant in place of the Target's own credential: remove \
                 target.auth"
            }
            Self::CallerCredentialForwarded => {
                "consent_mode external sends the grant in place of the caller's credential: turn the Access \
                 Point's forward_header off"
            }
            Self::CallersCharged => {
                "consent_mode external charges callers nothing: a payment is settled before the grant is \
                 released, and the release can still be refused; remove target.payment_policy"
            }
            Self::PresentationOfTheAgent => {
                "consent_mode external sends the vendor no presentation of the agent: turn off \
                 target.identity_injection.inject_vp and target.workload_binding, remove \
                 identity_slots.inbound, and inject the surface's DID in a header, not protocol_native"
            }
            Self::CustomMetadata => {
                "consent_mode external sends the vendor nothing of the gateway's beside the grant: turn \
                 target.custom_metadata off"
            }
        }
    }
}

/// The first rule of the Access Point Target's binding `binding` that `view`
/// breaks: the binding sends the grant, in a header, in place of every other
/// credential, as the only binding of `outbound_credentials`, which would
/// otherwise apply on every Transit Point too, so the surface has none; and
/// the vendor is sent no presentation of the agent, no custom metadata and no
/// payment.
pub(crate) fn target_binding_violation(
    view: &AgentSurface,
    binding: &OutboundCredentialBinding,
) -> Option<TargetBindingViolation> {
    let violation = if view
        .outbound_credentials
        .len()
        != 1
    {
        TargetBindingViolation::OtherBindings
    } else if !view
        .transit_points()
        .is_empty()
    {
        TargetBindingViolation::TransitPoints
    } else if matches!(binding.inject_as, CredentialInjection::Meta { .. }) {
        TargetBindingViolation::InjectedIntoTheBody
    } else if sends_the_grant_across_the_origin(view) {
        TargetBindingViolation::AtTheOriginRoot
    } else if view.target_auth().is_some() {
        TargetBindingViolation::TargetAuth
    } else if view.forwards_caller_credential() {
        TargetBindingViolation::CallerCredentialForwarded
    } else if view.charges_callers() {
        TargetBindingViolation::CallersCharged
    } else if view.presents_the_agent_to_the_target() {
        TargetBindingViolation::PresentationOfTheAgent
    } else if view.injects_custom_metadata() {
        TargetBindingViolation::CustomMetadata
    } else {
        return None;
    };
    Some(violation)
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
) -> Result<Option<TargetGrantRoute>, TargetGrantRefusal> {
    use crate::audit::request_events::{RejectionReason, RejectionStage, request_rejected};
    let request_facts = request.facts;
    route_unaudited(state, request)
        .await
        .inspect_err(|refused| {
            let reason = match refused {
                TargetGrantRefusal::Version => RejectionReason::VersionUnsupported,
                TargetGrantRefusal::Path => RejectionReason::TargetPathRefused,
                TargetGrantRefusal::Method => RejectionReason::TargetMethodRefused,
                TargetGrantRefusal::CallerNotIdentified => RejectionReason::ConsentIdentityRequired,
                TargetGrantRefusal::Grant(_)
                | TargetGrantRefusal::RetryNotSent
                | TargetGrantRefusal::RequestNotBuilt => RejectionReason::ConnectorUnavailable,
            };
            request_rejected(
                request_facts,
                RejectionStage::Admission,
                reason,
                refused.status().as_u16(),
                refused
                    .rpc_error_code(speaks_mcp(&state.surface))
                    .map(i64::from),
            );
        })
}

/// [`route`], without its audit.
async fn route_unaudited(
    state: &ProxyState,
    request: TargetRequest<'_>,
) -> Result<Option<TargetGrantRoute>, TargetGrantRefusal> {
    let surface = &state.surface;
    let Some(binding) = surface.target_external_credentials() else {
        return Ok(None);
    };
    let mcp = speaks_mcp(surface);
    if request.modern {
        warn!(
            target: "credential_delegation",
            surface_id = %surface.surface_id,
            surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
            "A 2026-07-28 MCP request was sent to an Access Point whose Target is bound by external consent - \
             refusing the request"
        );
        return Err(TargetGrantRefusal::Version);
    }
    let Some(segments) = forwarded_segments(request.path) else {
        log_refusal(surface, "path_not_read_alike");
        return Err(TargetGrantRefusal::Path);
    };
    if crate::proxy::paths::is_public_request(request.method, request.path) {
        return Ok(None);
    }
    if mcp && !segments.is_empty() {
        log_refusal(surface, "path_not_the_endpoint");
        return Err(TargetGrantRefusal::Path);
    }
    if mcp
        && ((request.method == "GET" && crate::mcp::sse_server::client_wants_sse(request.headers))
            || request.method == "DELETE")
    {
        return Ok(None);
    }
    if !methods_with_the_grant(mcp).contains(&request.method) {
        log_refusal(surface, "method_not_sent_the_grant");
        return Err(TargetGrantRefusal::Method);
    }
    if request
        .query
        .is_some_and(|query| !query.is_empty())
    {
        log_refusal(surface, "query_not_sent");
        return Err(TargetGrantRefusal::Path);
    }
    let Some(target_url) = forwarded_url(&surface.target.endpoint, &segments) else {
        return Err(unavailable(surface, "target_not_a_url"));
    };
    let Some(subject) = binding.subject else {
        return Err(unavailable(surface, "no_subject"));
    };
    if let Some(unchecked) = unchecked_callers(surface, subject) {
        return Err(unavailable(surface, unchecked.reason()));
    }
    if let Some(violation) = target_binding_violation(surface, binding) {
        return Err(unavailable(surface, violation.reason()));
    }
    let (Some(_), Some(providers)) = (&state.delegation_vault_store, &state.credential_provider_store) else {
        return Err(unavailable(surface, "stores_unavailable"));
    };
    let provider = match providers
        .get(&binding.credential_provider_id)
        .await
    {
        Ok(Some(provider)) => provider,
        Ok(None) | Err(_) => return Err(unavailable(surface, "provider_unavailable")),
    };
    if !provider.is_external_consent() {
        return Err(unavailable(surface, "provider_without_issuer"));
    }
    if provider.tenant_id != surface.tenant_id {
        return Err(unavailable(surface, "provider_of_another_tenant"));
    }
    let allowlist = state
        .egress_allowlist
        .as_deref();
    if crate::credential_providers::external::check_grant_destination(&provider, &target_url, allowlist)
        .await
        .is_err()
    {
        return Err(unavailable(surface, "destination_not_the_resource"));
    }
    if !crate::credential_providers::external::resource_permitted(
        &provider,
        &state
            .network_config
            .external_consent_resource_origins,
    ) {
        return Err(unavailable(surface, "resource_not_permitted_for_issuer"));
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
        return Err(unavailable(surface, "issuer_not_permitted"));
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
            unavailable(surface, "forward_refused_by_strict_egress")
        })?;
    Ok(Some(TargetGrantRoute {
        binding: binding.clone(),
        subject,
        provider,
        target_url,
        client,
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
/// use such a Target, so nothing needs its discovery there. A refusal is
/// audited `request_rejected` at admission, as `consent_identity_required`.
/// Any request to a Target that is not bound by external consent passes.
pub(crate) fn refuse_over_fabric(
    surface: &AgentSurface,
    body: &[u8],
    facts: &crate::audit::request_events::RequestFacts<'_>,
) -> Option<Response> {
    use crate::audit::request_events::{RejectionReason, RejectionStage, request_rejected};

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
    let refused = caller_not_identified(surface.access_point.protocol == SurfaceProtocol::Mcp, body);
    request_rejected(
        facts,
        RejectionStage::Admission,
        RejectionReason::ConsentIdentityRequired,
        refused.status().as_u16(),
        None,
    );
    Some(refused)
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
    ) -> Result<ReleasedTargetGrant, TargetGrantRefusal> {
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
            return Err(TargetGrantRefusal::CallerNotIdentified);
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
                    None => return Err(unavailable(surface, "caller_without_identity_hash")),
                }
            }
        };
        let Some(release) = self.release_context(state) else {
            return Err(unavailable(surface, "stores_unavailable"));
        };
        let grant = match release
            .release(&self.provider, &key, self.subject)
            .await
        {
            Ok(grant) => grant,
            Err(refused) => return Err(refuse(surface, refused)),
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
                Refused {
                    refusal: GrantRefusal::connect_required(&key, self.subject),
                    reason: "grant_beyond_the_bindings_scopes",
                },
            ));
        }
        let headers = self
            .headers_for(&grant)
            .ok_or_else(|| unavailable(surface, "grant_not_a_header_value"))?;
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
    /// `released`'s caller: mark it used, at most once per use interval and
    /// on its own task, and audit it under that caller's identity hash,
    /// whichever subject the binding has.
    async fn injected(
        &self,
        surface: &AgentSurface,
        release: &ReleaseContext<'_>,
        released: &ReleasedTargetGrant,
        grant: &DelegatedGrant,
    ) {
        if grant.use_is_due(chrono::Utc::now()) {
            let vault = Arc::clone(release.vault);
            let id = grant.id.clone();
            let surface_id = surface.surface_id.clone();
            tokio::spawn(async move {
                if let Err(error) = vault
                    .mark_grant_used(&id)
                    .await
                {
                    tracing::debug!(
                        target: "credential_delegation",
                        surface_id = %surface_id,
                        error = %error,
                        "Failed to record a grant's use"
                    );
                }
            });
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
    /// whose refresh token is refused, or a caller's grant that cannot be
    /// refreshed, is removed and revoked while it still holds the token
    /// refused, and an owner's that cannot be refreshed is kept; each answers
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
    ) -> Result<reqwest::Response, TargetGrantRefusal> {
        use crate::delegation_vault::release::{VendorAnswer, vendor_answer, vendor_answer_to_a_retry};
        let surface = &state.surface;
        match vendor_answer(response.status(), response.headers()) {
            VendorAnswer::Pass => return Ok(response),
            VendorAnswer::Refuse(refused) => {
                return Err(refuse(surface, refused));
            }
            VendorAnswer::TokenRejected => drop(response),
        }
        let Some(release) = self.release_context(state) else {
            return Err(unavailable(surface, "stores_unavailable"));
        };
        let fresh = match release
            .retry_grant(&self.provider, &released.key, self.subject, &released.grant, retry.is_some())
            .await
        {
            Ok(fresh) => fresh,
            Err(refused) => {
                return Err(refuse(surface, refused));
            }
        };
        let Some(retry) = retry else {
            return Err(unavailable(surface, "vendor_refused_a_large_body_refreshed_for_the_next_call"));
        };
        let Some(headers) = self.headers_for(&fresh) else {
            return Err(unavailable(surface, "grant_not_a_header_value"));
        };
        let (client, request) = retry.build_split();
        let Ok(mut request) = request else {
            return Err(unavailable(surface, "retry_not_rebuilt"));
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
                return Err(TargetGrantRefusal::RetryNotSent);
            }
        };
        if let Err(refused) = vendor_answer_to_a_retry(retried.status(), retried.headers()) {
            drop(retried);
            return Err(refuse(surface, refused));
        }
        Ok(retried)
    }
}

impl ReleasedTargetGrant {
    /// `request` with the grant's headers in place of any of the same name.
    pub(crate) fn apply(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, TargetGrantRefusal> {
        let (client, built) = request.build_split();
        let mut built = built.map_err(|_| TargetGrantRefusal::RequestNotBuilt)?;
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
        use crate::audit::request_events::{RejectionReason, RejectionStage, RequestFacts};
        use crate::delegation_vault::audit::DelegationAuditAction;

        let external = serde_json::json!([{"credential_provider_id": "vendor", "consent_mode": "external",
            "subject": "owner"}]);
        let call = br#"{"jsonrpc":"2.0","id":"call-1","method":"tools/list"}"#;
        type Rejection = (RejectionStage, RejectionReason, Option<u16>, Option<i64>);
        async fn refuse(
            protocol: &str,
            bindings: serde_json::Value,
            body: &[u8],
        ) -> (Option<Response>, Vec<Rejection>) {
            let facts = RequestFacts {
                via_fabric: true,
                ..RequestFacts::unroutable()
            };
            let (refused, events) = crate::audit::producer::capture(async {
                refuse_over_fabric(&surface(protocol, bindings), body, &facts)
            })
            .await;
            let rejections = events
                .into_iter()
                .filter_map(|event| match event.event {
                    DelegationAuditAction::RequestRejected {
                        stage,
                        reason,
                        http_status,
                        rpc_error_code,
                        ..
                    } => Some((stage, reason, http_status, rpc_error_code)),
                    _ => None,
                })
                .collect();
            (refused, rejections)
        }
        let (refused, rejections) = refuse("mcp", external.clone(), call).await;
        let (status, body) = read(refused.expect("a Fabric caller is refused")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["id"], "call-1");
        assert_eq!(body["error"]["code"], -32001);
        assert_eq!(rejections, [(RejectionStage::Admission, RejectionReason::ConsentIdentityRequired, None, None)]);
        let (refused, rejections) = refuse("a2a", external.clone(), call).await;
        let (status, body) = read(refused.expect("a Fabric caller is refused")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["type"], "https://affinidi.com/atg/errors/identity-required");
        assert_eq!(rejections, [(RejectionStage::Admission, RejectionReason::ConsentIdentityRequired, None, None)]);
        let (refused, rejections) = refuse("a2a", external, b"").await;
        assert_eq!(
            read(refused.expect("a Fabric discovery read, without a body"))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(rejections.len(), 1, "a discovery read is audited too");
        let (refused, rejections) =
            refuse("mcp", serde_json::json!([{"credential_provider_id": "agent-keyed"}]), call).await;
        assert!(refused.is_none());
        assert!(rejections.is_empty(), "a request let through is not audited");
    }

    /// Each rule of the Access Point Target's binding is one violation, found
    /// in the same view at save and at run time, with a reason and a refusal of
    /// its own; a view that breaks none has none.
    #[test]
    fn each_rule_of_the_targets_binding_is_one_violation_at_save_and_run_time() {
        let external = serde_json::json!({"credential_provider_id": "vendor", "consent_mode": "external",
            "subject": "owner"});
        let with = |change: serde_json::Value| {
            let mut view = serde_json::to_value(surface("mcp", serde_json::json!([external.clone()]))).unwrap();
            json_patch::merge(&mut view, &change);
            serde_json::from_value::<AgentSurface>(view).unwrap()
        };
        let cases = [
            (
                TargetBindingViolation::OtherBindings,
                with(serde_json::json!({"outbound_credentials": [external.clone(),
                    {"credential_provider_id": "agent-keyed"}]})),
            ),
            (
                TargetBindingViolation::TransitPoints,
                with(serde_json::json!({"transit": {"points": [{"alias": "crm",
                    "target_endpoint": "https://crm.example/mcp"}]}})),
            ),
            (
                TargetBindingViolation::InjectedIntoTheBody,
                with(serde_json::json!({"outbound_credentials": [{"credential_provider_id": "vendor",
                    "consent_mode": "external", "subject": "owner", "inject_as": {"type": "meta", "field": "token"}}]})),
            ),
            (
                TargetBindingViolation::AtTheOriginRoot,
                with(serde_json::json!({"access_point": {"protocol": "a2a"},
                    "target": {"endpoint": "https://mcp.vendor.example"}})),
            ),
            (
                TargetBindingViolation::TargetAuth,
                with(
                    serde_json::json!({"target": {"auth": {"method": {"static_secret": {"secret_id": "s", "header_name": "X-Api-Key"}}}}}),
                ),
            ),
            (
                TargetBindingViolation::CallersCharged,
                with(serde_json::json!({"target": {"payment_policy": {"type": "x402", "enabled": true}}})),
            ),
            (
                TargetBindingViolation::PresentationOfTheAgent,
                with(serde_json::json!({"target": {"workload_binding": {"enabled": true}}})),
            ),
            (
                TargetBindingViolation::CustomMetadata,
                with(serde_json::json!({"target": {"custom_metadata": {"enabled": true, "payload": {"a": "b"}}}})),
            ),
        ];
        let mut reasons = std::collections::HashSet::new();
        let mut refusals = std::collections::HashSet::new();
        for (expected, view) in &cases {
            let binding = view
                .target_external_credentials()
                .unwrap();
            assert_eq!(target_binding_violation(view, binding), Some(*expected), "{expected:?}");
            assert!(reasons.insert(expected.reason()), "{expected:?} has a reason of its own");
            assert!(refusals.insert(expected.refusal()), "{expected:?} has a refusal of its own");
        }
        let clean = with(serde_json::json!({}));
        assert_eq!(
            target_binding_violation(
                &clean,
                clean
                    .target_external_credentials()
                    .unwrap()
            ),
            None
        );
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
