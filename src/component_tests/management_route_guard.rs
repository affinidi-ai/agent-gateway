//! Walks the management API router that `create_identity_api_router` builds and checks that
//! every route inside the session boundary is behind a feature guard or is listed in
//! [`ALLOW_LIST`] with the reason it is not.
//!
//! The walk covers that router as [`ManagementApi`] builds it, with a passkey auth backend and
//! WebSocket authentication on: identity, settings, metrics, logs, configuration, surfaces,
//! surface templates, policies, users and profiles, terms, notifications, gateways, connection
//! points, mediators, issuers, authorities, MCP and A2A proxies, trust registries, integrations,
//! did:webvh identities, JWT verification strategies, token service clients, and the x402 and
//! MPP admin APIs. It does not walk:
//!
//! - the SAML sign-in routes, mounted only with a SAML backend;
//! - the debug-only test sign-in route, which the tests keep unmounted;
//! - the MCP authorization server routes, mounted only when the token service has an MCP issuer;
//! - the WebSocket routes as mounted with `websocket_require_auth` off;
//! - the routes the server assembles outside this constructor: the vault routes (secrets,
//!   certificates, API keys, access tokens, vault identities, credential providers and the
//!   delegation vault), the delegation vault OAuth callback and consent routes merged after the
//!   vault's session layer, and the separate public root DID and onboarding routers;
//! - the router built without an auth backend, beyond the five routes its own test probes;
//! - the router's fallback, which answers paths no route matches.
//!
//! The probes check that a route refuses a caller who holds no feature, not that its guard
//! names the feature the route serves.
//!
//! Routes are read from axum's `Router` Debug output. [`walked_routes`] fails a test when it
//! finds fewer routes than a floor or misses a sentinel route, so a change in that output or a
//! router that drops out cannot pass silently.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::LazyLock;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use regex::{Captures, Regex};
use tower::ServiceExt;

use crate::auth::types::UserRole;
use crate::component_tests::helpers::management_api::{ManagementApi, runs_without_test_mode};
use crate::rbac::{Feature, RbacConfig};

use Allowance::{HandlerChecked, Public, RoleOnly, SignedIn};

const ANY_METHOD: &str = "ANY";
const METHODS: [&str; 9] = ["GET", "HEAD", "DELETE", "OPTIONS", "PATCH", "POST", "PUT", "TRACE", "CONNECT"];
const MINIMUM_WALKED_ROUTES: usize = 250;
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const SCOPE_WITHOUT_FEATURE: &str = "unassigned";

/// Parses as the request body of every `HandlerChecked` route, so those handlers answer with
/// their own permission check rather than with a body rejection.
const PROBE_BODY: &str = r#"{"name":"probe","expected_issuer":"probe","jwks_source":{"type":"static","jwks":[]},"client_id":"probe","uri":""}"#;

const SENTINELS: [(&str, &str); 16] = [
    ("POST", "/v1/logs/truncate"),
    ("POST", "/v1/metrics/truncate"),
    ("GET", "/v1/users"),
    ("GET", "/v1/notifications/user-welcome-template"),
    ("GET", "/admin/x402/stats"),
    ("GET", "/admin/mpp/transactions"),
    ("GET", "/v1/gateways"),
    ("GET", "/v1/connection-points"),
    ("GET", "/v1/mediators"),
    ("GET", "/v1/issuers"),
    ("GET", "/v1/authorities"),
    ("GET", "/v1/mcp-proxies"),
    ("GET", "/v1/a2a-proxies"),
    ("GET", "/v1/trust-registries"),
    ("GET", "/v1/integrations"),
    ("GET", "/v1/identities"),
];

/// `RoleOnly` routes whose handler reaches its role check with [`PROBE_BODY`] and `probe` path
/// parameters, so the session probe expects their 403 too. The other `RoleOnly` handlers reject
/// the body or look up the named record first.
const ROLE_CHECKS_THE_PROBE_REACHES: [(&str, &str); 5] = [
    ("GET", "/v1/users"),
    ("GET", "/v1/users/{user_id}"),
    ("POST", "/v1/settings"),
    ("DELETE", "/v1/settings"),
    ("POST", "/v1/admin/backup-storage"),
];

static ROUTE_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"RouteId\((?<id>\d+)\): "(?<path>[^"]*)""#).expect("route path pattern"));

static ROUTE_ENDPOINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"RouteId\((?<id>\d+)\): (?:Route\(|MethodRouter\(MethodRouter \{ ",
        r"get: (?<get>\w+), head: (?<head>\w+), delete: (?<delete>\w+), options: (?<options>\w+), ",
        r"patch: (?<patch>\w+), post: (?<post>\w+), put: (?<put>\w+), trace: (?<trace>\w+), ",
        r"connect: (?<connect>\w+), fallback: (?<fallback>\w+))",
    ))
    .expect("route endpoint pattern")
});

static PATH_PARAMETER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\*?[^}]+\}").expect("path parameter pattern"));

enum Allowance {
    /// Answers without a session.
    Public(&'static str),
    /// Answers any approved user's session. Most of these handlers also serve an access token;
    /// the notification handlers validate the bearer as a session, so a token gets an empty
    /// list, a zero count or 401 from them.
    SignedIn(&'static str),
    /// The handler checks the caller's role and the access token's scopes for the feature.
    HandlerChecked(Feature),
    /// The handler checks the caller's role for the feature; access-token scopes do not apply.
    RoleOnly(Feature),
}

impl fmt::Display for Allowance {
    fn fmt(
        &self,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        match self {
            Public(reason) => write!(formatter, "public: {reason}"),
            SignedIn(reason) => write!(formatter, "any signed-in caller: {reason}"),
            HandlerChecked(feature) => {
                write!(formatter, "handler checks role and token scope for {}", feature.as_str())
            }
            RoleOnly(feature) => write!(formatter, "handler checks role for {}", feature.as_str()),
        }
    }
}

const ALLOW_LIST: &[(Allowance, &[(&str, &str)])] = &[
    (
        Public("avatar images, served outside the session layer"),
        &[
            (ANY_METHOD, "/avatars"),
            (ANY_METHOD, "/avatars/"),
            (ANY_METHOD, "/avatars/{*__private__axum_nest_tail_param}"),
        ],
    ),
    (Public("DIDComm messages from other agents"), &[("POST", "/didcomm"), ("GET", "/didcomm/ws")]),
    (Public("DID resolution"), &[("GET", "/v1/identity/resolve-did"), ("GET", "/v1/identity/resolve-did-document")]),
    (Public("did:webvh resolution"), &[("GET", "/v1/resolve")]),
    (Public("published did:webvh logs"), &[("GET", "/dids/{*path}")]),
    (
        Public("published connection point DID document"),
        &[("GET", "/connection-points/{cp_id}/did.json"), ("GET", "/.well-known/connection-points/{cp_id}/did.json")],
    ),
    (
        Public("published connection point DID log"),
        &[("GET", "/connection-points/{cp_id}/did.jsonl"), ("GET", "/.well-known/connection-points/{cp_id}/did.jsonl")],
    ),
    (Public("published trust registry DID document"), &[("GET", "/.well-known/trust-registries/{tr_id}/did.json")]),
    (Public("readiness probe"), &[("GET", "/v1/health")]),
    (Public("liveness probe"), &[("GET", "/v1/alive")]),
    (Public("build version"), &[("GET", "/v1/version")]),
    (Public("Prometheus scrape, with optional Basic auth from settings"), &[("GET", "/v1/metrics/prometheus")]),
    (
        Public("agent onboarding addressed by its session id"),
        &[
            ("GET", "/onboard/{uuid}/.well-known/agent-card.json"),
            ("POST", "/onboard/{uuid}"),
            ("POST", "/onboard/{uuid}/"),
            ("POST", "/onboard/{uuid}/rpc"),
        ],
    ),
    (Public("local agent self-registration"), &[("POST", "/agents-api/v1/onboard")]),
    (Public("verification of a presented JWT"), &[("POST", "/agents-api/v1/verify-jwt")]),
    (Public("the configured sign-in method"), &[("GET", "/v1/auth/mode")]),
    (Public("passkey registration"), &[("POST", "/auth/register/start"), ("POST", "/auth/register/finish")]),
    (Public("passkey sign-in"), &[("POST", "/auth/login/start"), ("POST", "/auth/login/finish")]),
    (Public("session check for the sign-in page"), &[("GET", "/auth/check")]),
    (Public("sign-out"), &[("POST", "/auth/logout")]),
    (Public("CLI sign-in"), &[("GET", "/auth/cli/authorize"), ("POST", "/auth/cli/exchange")]),
    (Public("CLI sign-in consent, which checks the browser session itself"), &[("POST", "/auth/cli/consent")]),
    (Public("permissions shown during registration"), &[("GET", "/v1/permissions/public")]),
    (Public("terms shown before sign-in"), &[("GET", "/v1/terms/applicable")]),
    (Public("terms provider status shown before sign-in"), &[("GET", "/v1/terms/provider-health")]),
    (
        Public("dashboard WebSocket, which checks the session in its handshake"),
        &[("GET", "/ws"), ("GET", "/ws/dashboard")],
    ),
    (Public("token exchange, authenticated by client credentials"), &[("POST", "/oauth2/token")]),
    (Public("token service signing keys"), &[("GET", "/oauth2/jwks.json")]),
    (Public("token service metadata"), &[("GET", "/.well-known/oauth-authorization-server")]),
    (SignedIn("the gateway's own DID document"), &[("GET", "/v1/identity/did-document")]),
    (SignedIn("dashboard display settings"), &[("GET", "/v1/settings")]),
    (SignedIn("static catalogue of audit event types"), &[("GET", "/v1/settings/audit-events")]),
    (SignedIn("metrics exporter connection status"), &[("GET", "/v1/metrics/otlp-status")]),
    (SignedIn("listen addresses and route prefixes for the surface editor"), &[("GET", "/v1/config/surface-routing")]),
    (SignedIn("payment settings for the surface editor"), &[("GET", "/v1/config/x402")]),
    (SignedIn("networking settings for the dashboard"), &[("GET", "/v1/config/networking")]),
    (SignedIn("Rego compile check that stores nothing"), &[("POST", "/v1/surfaces/validate-policy")]),
    (SignedIn("agents known to the gateway, for the dashboard"), &[("GET", "/v1/agents")]),
    (
        SignedIn("dashboard home figures"),
        &[
            ("GET", "/v1/dashboard/stats"),
            ("GET", "/v1/dashboard/delta"),
            ("GET", "/v1/dashboard/surface/{channel_config_id}/metrics"),
            ("GET", "/v1/dashboard/surface/{channel_config_id}/ucp-operations"),
            ("GET", "/v1/dashboard/metrics/hierarchical"),
            ("GET", "/v1/dashboard/system-metrics"),
        ],
    ),
    (
        SignedIn("the caller's own notifications"),
        &[
            ("GET", "/v1/notifications"),
            ("POST", "/v1/notifications"),
            ("GET", "/v1/notifications/{id}"),
            ("PUT", "/v1/notifications/{id}"),
            ("DELETE", "/v1/notifications/{id}"),
            ("GET", "/v1/notifications/unread/count"),
        ],
    ),
    (
        SignedIn("the caller's own profile"),
        &[("GET", "/v1/profile"), ("PUT", "/v1/profile"), ("POST", "/v1/profile/avatar")],
    ),
    (SignedIn("the caller's own permissions"), &[("GET", "/v1/permissions")]),
    (SignedIn("the presented credential's own details"), &[("GET", "/v1/token-info")]),
    (
        SignedIn("the caller's own dashboard preferences"),
        &[
            ("GET", "/v1/user-settings"),
            ("POST", "/v1/user-settings"),
            ("DELETE", "/v1/user-settings"),
            ("GET", "/v1/user-settings/overrides"),
        ],
    ),
    (SignedIn("the caller's own terms acceptance"), &[("GET", "/v1/terms/status"), ("POST", "/v1/terms/acceptances")]),
    (
        SignedIn("permanent redirect from a legacy departments path to the matching issuers route"),
        &[
            (ANY_METHOD, "/v1/departments"),
            (ANY_METHOD, "/v1/departments/{id}"),
            (ANY_METHOD, "/v1/departments/{id}/register-trust-registry"),
            (ANY_METHOD, "/v1/admin/departments/migrate-to-webvh"),
        ],
    ),
    (
        SignedIn("trust registry DID document, also served at the root"),
        &[("GET", "/trust-registries/{tr_id}/did.json")],
    ),
    (SignedIn("trust registry DID log, also served at the root"), &[("GET", "/trust-registries/{tr_id}/did.jsonl")]),
    (
        SignedIn("trust registry DID witness proofs, also served at the root"),
        &[("GET", "/trust-registries/{tr_id}/did-witness.json")],
    ),
    (SignedIn("static catalogue of trust check queries"), &[("GET", "/v1/trust-check/predefined-queries")]),
    (SignedIn("did:webvh log verification of a DID"), &[("POST", "/v1/verify/{did}")]),
    (RoleOnly(Feature::UsersView), &[("GET", "/v1/users"), ("GET", "/v1/users/{user_id}")]),
    (RoleOnly(Feature::UsersEdit), &[("PUT", "/v1/users/{user_id}")]),
    (RoleOnly(Feature::UsersDelete), &[("DELETE", "/v1/users/{user_id}")]),
    (
        RoleOnly(Feature::SettingsEdit),
        &[("POST", "/v1/settings"), ("DELETE", "/v1/settings"), ("POST", "/agents-api/v1/sign-jwt")],
    ),
    (
        RoleOnly(Feature::StorageAdmin),
        &[
            ("POST", "/v1/admin/backup-storage"),
            ("POST", "/v1/admin/restore-storage"),
            ("POST", "/v1/debug/export-storage"),
        ],
    ),
    (
        HandlerChecked(Feature::JwtVerificationStrategiesView),
        &[
            ("GET", "/v1/jwt-verification-strategies"),
            ("POST", "/v1/jwt-verification-strategies/validate-jwks-uri"),
            ("GET", "/v1/jwt-verification-strategies/{id}"),
        ],
    ),
    (
        HandlerChecked(Feature::JwtVerificationStrategiesEdit),
        &[("POST", "/v1/jwt-verification-strategies"), ("PUT", "/v1/jwt-verification-strategies/{id}")],
    ),
    (HandlerChecked(Feature::JwtVerificationStrategiesDelete), &[("DELETE", "/v1/jwt-verification-strategies/{id}")]),
    (HandlerChecked(Feature::StsClientsView), &[("GET", "/v1/sts/clients"), ("GET", "/v1/sts/clients/{id}")]),
    (HandlerChecked(Feature::StsClientsEdit), &[("POST", "/v1/sts/clients"), ("PUT", "/v1/sts/clients/{id}")]),
    (HandlerChecked(Feature::StsClientsDelete), &[("DELETE", "/v1/sts/clients/{id}")]),
];

/// Every allow-listed (method, path) with its allowance.
fn allow_listed() -> impl Iterator<Item = (&'static str, &'static str, &'static Allowance)> {
    ALLOW_LIST
        .iter()
        .flat_map(|(allowance, routes)| {
            routes
                .iter()
                .map(move |(method, path)| (*method, *path, allowance))
        })
}

fn allowance(
    method: &str,
    path: &str,
) -> Option<&'static Allowance> {
    allow_listed()
        .find(|(listed_method, listed_path, _)| *listed_method == method && *listed_path == path)
        .map(|(_, _, allowance)| allowance)
}

/// Whether a route must refuse a caller who lacks the feature it serves: every route outside
/// the allow-list, and the allow-listed ones whose handler checks that feature itself.
fn checks_the_feature(allowance: Option<&Allowance>) -> bool {
    matches!(allowance, None | Some(HandlerChecked(_)))
}

/// Whether `status` shows the credential reached the handler: neither 401 nor 403.
fn admits(status: StatusCode) -> bool {
    status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN
}

fn named_group<'haystack>(
    capture: &Captures<'haystack>,
    name: &str,
) -> &'haystack str {
    capture
        .name(name)
        .unwrap_or_else(|| panic!("no {name} group in the match"))
        .as_str()
}

/// The (method, path) pairs `router` serves, with `ANY` for a path that takes every method.
fn registered_routes(router: &Router) -> BTreeSet<(String, String)> {
    let debug = format!("{router:?}");
    let (path_router, _) = debug
        .split_once("fallback_router:")
        .expect("the Router Debug output names its fallback router");
    let path_of: HashMap<&str, &str> = ROUTE_PATH
        .captures_iter(path_router)
        .map(|capture| (named_group(&capture, "id"), named_group(&capture, "path")))
        .collect();
    let mut routes = BTreeSet::new();
    for capture in ROUTE_ENDPOINT.captures_iter(path_router) {
        let path = path_of[named_group(&capture, "id")].to_string();
        let Some(fallback) = capture.name("fallback") else {
            routes.insert((ANY_METHOD.to_string(), path));
            continue;
        };
        if fallback.as_str() != "Default" {
            routes.insert((ANY_METHOD.to_string(), path.clone()));
        }
        for method in METHODS {
            if named_group(&capture, &method.to_ascii_lowercase()) != "None" {
                routes.insert((method.to_string(), path.clone()));
            }
        }
    }
    routes
}

/// The routes of `router` every probe walks. Fails the calling test when the walk finds fewer
/// than [`MINIMUM_WALKED_ROUTES`] or misses one of the [`SENTINELS`], so no probe can pass on a
/// walk that found nothing.
fn walked_routes(router: &Router) -> BTreeSet<(String, String)> {
    let routes = registered_routes(router);
    assert!(
        routes.len() >= MINIMUM_WALKED_ROUTES,
        "the walk found {} routes, fewer than {MINIMUM_WALKED_ROUTES}",
        routes.len()
    );
    let missing_sentinels: Vec<String> = SENTINELS
        .iter()
        .filter(|(method, path)| !routes.contains(&(method.to_string(), path.to_string())))
        .map(|(method, path)| format!("{method} {path}"))
        .collect();
    assert!(missing_sentinels.is_empty(), "sentinel routes the walk did not find:\n{}", missing_sentinels.join("\n"));
    routes
}

/// The status `router` answers `method` on `path`, with every path parameter set to `probe`,
/// or `None` when it does not answer within [`PROBE_TIMEOUT`].
async fn status_of(
    router: &Router,
    method: &str,
    path: &str,
    credential: Option<&str>,
) -> Option<StatusCode> {
    let method = match method {
        ANY_METHOD => Method::GET,
        other => Method::from_bytes(other.as_bytes()).expect("method"),
    };
    let path = PATH_PARAMETER
        .replace_all(path, "probe")
        .into_owned();
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(credential) = credential {
        request = request.header(header::AUTHORIZATION, format!("Bearer {credential}"));
    }
    let request = request
        .body(Body::from(PROBE_BODY))
        .expect("request");
    tokio::time::timeout(
        PROBE_TIMEOUT,
        router
            .clone()
            .oneshot(request),
    )
    .await
    .ok()
    .map(|response| {
        response
            .expect("the router is infallible")
            .status()
    })
}

/// Every walked route of `api` that `probed` selects and whose answer to a request carrying
/// `credential` is not `expected`, as "method path answered status (allowance)".
async fn routes_not_answering(
    api: &ManagementApi,
    credential: Option<&str>,
    probed: impl Fn(&str, &str, Option<&Allowance>) -> bool,
    expected: impl Fn(StatusCode) -> bool,
) -> Vec<String> {
    let mut offenders = Vec::new();
    for (method, path) in walked_routes(&api.router) {
        let allowance = allowance(&method, &path);
        if !probed(&method, &path, allowance) {
            continue;
        }
        let status = status_of(&api.router, &method, &path, credential).await;
        if !status.is_some_and(&expected) {
            let answer = status.map_or_else(|| "nothing before the timeout".to_string(), |status| status.to_string());
            let listing = allowance.map_or_else(|| "not allow-listed".to_string(), ToString::to_string);
            offenders.push(format!("{method} {path} answered {answer} ({listing})"));
        }
    }
    offenders
}

#[tokio::test]
async fn the_route_walk_finds_the_registered_routes_and_no_stale_exemptions() {
    if !runs_without_test_mode() {
        return;
    }
    let api = ManagementApi::with_auth_backend(RbacConfig::default()).await;
    let routes = walked_routes(&api.router);
    let registered = |method: &str, path: &str| routes.contains(&(method.to_string(), path.to_string()));

    let stale_entries: Vec<String> = allow_listed()
        .filter(|(method, path, _)| !registered(method, path))
        .map(|(method, path, allowance)| format!("{method} {path} ({allowance})"))
        .collect();
    assert!(
        stale_entries.is_empty(),
        "allow-list entries that name no registered route:\n{}",
        stale_entries.join("\n")
    );
    let distinct_entries: BTreeSet<(&str, &str)> = allow_listed()
        .map(|(method, path, _)| (method, path))
        .collect();
    assert_eq!(distinct_entries.len(), allow_listed().count(), "the allow-list names a route twice");
    let not_role_only: Vec<String> = ROLE_CHECKS_THE_PROBE_REACHES
        .iter()
        .filter(|(method, path)| !matches!(allowance(method, path), Some(RoleOnly(_))))
        .map(|(method, path)| format!("{method} {path}"))
        .collect();
    assert!(
        not_role_only.is_empty(),
        "role checks the probe reaches on routes without a role-only allow-list entry:\n{}",
        not_role_only.join("\n")
    );
}

#[tokio::test]
async fn every_route_except_public_ones_refuses_a_request_without_credentials() {
    if !runs_without_test_mode() {
        return;
    }
    let api = ManagementApi::with_auth_backend(RbacConfig::default()).await;

    let offenders = routes_not_answering(
        &api,
        None,
        |_, _, allowance| !matches!(allowance, Some(Public(_))),
        |status| status == StatusCode::UNAUTHORIZED,
    )
    .await;

    assert_eq!(
        status_of(&api.router, "GET", "/v1/health", None).await,
        Some(StatusCode::OK),
        "the readiness probe answers a request without credentials"
    );
    assert!(
        offenders.is_empty(),
        "routes that do not answer 401 to a request without credentials:\n{}",
        offenders.join("\n")
    );
}

#[tokio::test]
async fn every_session_route_is_feature_gated_or_allow_listed() {
    if !runs_without_test_mode() {
        return;
    }
    let api = ManagementApi::with_auth_backend(RbacConfig { permissions: HashMap::new() }).await;
    let session = api
        .session(UserRole::Administrator)
        .await;

    let refused_signed_in_routes =
        routes_not_answering(&api, Some(&session), |_, _, allowance| matches!(allowance, Some(SignedIn(_))), admits)
            .await;
    let reached_routes = routes_not_answering(
        &api,
        Some(&session),
        |method, path, allowance| {
            checks_the_feature(allowance) || ROLE_CHECKS_THE_PROBE_REACHES.contains(&(method, path))
        },
        |status| status == StatusCode::FORBIDDEN,
    )
    .await;

    assert!(
        refused_signed_in_routes.is_empty(),
        "signed-in routes that refuse an approved administrator's session; a route that now has a feature \
         guard needs its allow-list entry removed:\n{}",
        refused_signed_in_routes.join("\n")
    );
    assert!(
        reached_routes.is_empty(),
        "routes an administrator without any permission reaches; give each a feature guard or an allow-list \
         entry with its reason:\n{}",
        reached_routes.join("\n")
    );
}

#[tokio::test]
async fn a_narrowly_scoped_administrator_token_is_refused_outside_the_allow_list() {
    if !runs_without_test_mode() {
        return;
    }
    let api = ManagementApi::with_auth_backend(RbacConfig::default()).await;
    let token = api
        .access_token(UserRole::Administrator, &[SCOPE_WITHOUT_FEATURE])
        .await;
    let gateways_token = api
        .access_token(UserRole::Administrator, &[Feature::GatewaysView.as_str()])
        .await;

    let offenders = routes_not_answering(
        &api,
        Some(&token),
        |_, _, allowance| checks_the_feature(allowance),
        |status| status == StatusCode::FORBIDDEN,
    )
    .await;

    assert_eq!(
        [
            status_of(&api.router, "GET", "/v1/token-info", Some(&token)).await,
            status_of(&api.router, "GET", "/v1/gateways", Some(&gateways_token)).await,
        ],
        [Some(StatusCode::OK); 2],
        "the narrow token reads its own details, and a token scoped to gateways.view lists gateways"
    );
    assert!(
        offenders.is_empty(),
        "routes an administrator's access token scoped to no feature reaches:\n{}",
        offenders.join("\n")
    );
}

#[tokio::test]
async fn without_an_auth_backend_truncate_routes_are_absent_and_welcome_routes_refuse() {
    let api = ManagementApi::without_auth_backend().await;
    let rotated_log = api
        .log_directory
        .join("agent-gateway.log.1");
    std::fs::write(&rotated_log, "rotated").expect("rotated log");

    let mut answers = Vec::new();
    for (method, path) in [
        ("POST", "/v1/logs/truncate"),
        ("POST", "/v1/metrics/truncate"),
        ("GET", "/v1/notifications/user-welcome-template"),
        ("PUT", "/v1/notifications/user-welcome-template"),
        ("POST", "/v1/notifications/send-welcome"),
    ] {
        answers.push((method, path, status_of(&api.router, method, path, None).await));
    }

    assert_eq!(
        answers,
        vec![
            ("POST", "/v1/logs/truncate", Some(StatusCode::NOT_FOUND)),
            ("POST", "/v1/metrics/truncate", Some(StatusCode::NOT_FOUND)),
            ("GET", "/v1/notifications/user-welcome-template", Some(StatusCode::FORBIDDEN)),
            ("PUT", "/v1/notifications/user-welcome-template", Some(StatusCode::FORBIDDEN)),
            ("POST", "/v1/notifications/send-welcome", Some(StatusCode::FORBIDDEN)),
        ]
    );
    assert!(rotated_log.exists(), "the rotated log file was removed");
}
