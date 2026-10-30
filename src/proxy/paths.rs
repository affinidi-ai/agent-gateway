//! Shared path utilities for the proxy module.
//!
//! Defines which request paths are publicly accessible and must bypass all
//! authentication gates (OIDC, Trust Registry validation, etc.) regardless
//! of channel configuration.

/// Returns `true` for paths that are always publicly accessible and must
/// bypass all authentication gates (OIDC, Trust Registry, etc.) regardless
/// of how the channel is configured.
///
/// Adding a new public path here is the **single change** required — both
/// the OIDC gate and the Trust Registry gate use this predicate, so they
/// stay in sync automatically.
pub fn is_public_path(path: &str) -> bool {
    let path = path
        .split(['?', '#'])
        .next()
        .unwrap_or(path);
    let path = path
        .strip_suffix('/')
        .unwrap_or(path);

    is_well_known_agent_card_path(path)
        || path.ends_with("/agent-card.json")
        || path.ends_with("/agent.json")
        || path.ends_with("/.well-known/ucp")
        || path.ends_with("/.well-known/agent-card")
        || path.ends_with("/discovery")
}

/// The RFC 9728 well-known prefix every inbound listener serves protected resource
/// metadata under.
pub const PROTECTED_RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

/// Whether `route` is the protected resource metadata path or lies below it, where an
/// Access Point could never be reached.
pub fn is_protected_resource_metadata_route(route: &str) -> bool {
    route
        .strip_prefix(PROTECTED_RESOURCE_METADATA_PATH)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Whether `route` holds the `$` (or `%24`) that separates a Surface Variant alias, so
/// it would overlap another surface's variant URLs.
pub fn route_holds_variant_separator(route: &str) -> bool {
    route.contains('$') || route.contains("%24")
}

/// Whether `path` requests a well-known agent card (`agent-card.json` or the
/// legacy `agent.json`).
pub fn is_well_known_agent_card_path(path: &str) -> bool {
    path.ends_with("/.well-known/agent-card.json") || path.ends_with("/.well-known/agent.json")
}

/// Whether a request fetches the extended agent card over the A2A HTTP+JSON
/// binding: `{route}/extendedAgentCard` (1.0, also tenant-scoped as
/// `{route}/{tenant}/extendedAgentCard`) or `{route}/v1/card` (0.3).
///
/// The path is checked as the Target sees it: appended to the base path of
/// `target_endpoint`, resolved the way the forwarded URL is resolved, and also
/// the way lenient routers (Tomcat, Spring, JAX-RS) resolve it, which decode
/// `%2e`, drop `;` path parameters and empty segments, and treat `\` as a
/// separator. Matching ignores ASCII case. A path that climbs out of the base
/// path, climbs above the root (which covers a peer gateway's unknown base path
/// on `fabric://` targets), or cannot be parsed is treated as a card so the
/// response is still rewritten. Every method except `HEAD` and `OPTIONS` is checked, because a
/// Target may honour a method override header.
pub fn is_rest_extended_agent_card_request(
    method: &str,
    target_endpoint: &str,
    request_path: &str,
) -> bool {
    if method.eq_ignore_ascii_case("HEAD") || method.eq_ignore_ascii_case("OPTIONS") {
        return false;
    }
    let base_path = target_base_path(target_endpoint);
    let joined = format!("{}/{}", base_path.trim_end_matches('/'), request_path.trim_start_matches('/'));
    let Ok(forwarded) = url::Url::parse(&format!("http://route.invalid{joined}")) else {
        return true;
    };
    let base_segments = lenient_router_segments(&base_path).unwrap_or_default();
    let resolved = percent_decode_lossy(forwarded.path());
    [lenient_router_segments(&resolved), lenient_router_segments(&joined)]
        .iter()
        .any(|segments| {
            match segments
                .as_deref()
                .and_then(|segments| strip_base_segments(segments, &base_segments))
            {
                Some(route_relative) => is_extended_agent_card_segments(route_relative),
                None => true,
            }
        })
}

/// The path of an `http(s)` Target endpoint; other schemes, such as `fabric://`,
/// forward the request path unchanged.
fn target_base_path(target_endpoint: &str) -> String {
    url::Url::parse(target_endpoint)
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .map(|url| url.path().to_string())
        .unwrap_or_else(|| "/".to_string())
}

fn strip_base_segments<'a>(
    segments: &'a [String],
    base_segments: &[String],
) -> Option<&'a [String]> {
    if segments.len() < base_segments.len() {
        return None;
    }
    let (base, rest) = segments.split_at(base_segments.len());
    base.iter()
        .zip(base_segments)
        .all(|(segment, base_segment)| segment.eq_ignore_ascii_case(base_segment))
        .then_some(rest)
}

fn is_extended_agent_card_segments(segments: &[String]) -> bool {
    match segments {
        [.., last] if last.eq_ignore_ascii_case("extendedAgentCard") => true,
        [version, card] => version.eq_ignore_ascii_case("v1") && card.eq_ignore_ascii_case("card"),
        _ => false,
    }
}

fn percent_decode_lossy(path: &str) -> String {
    String::from_utf8_lossy(&urlencoding::decode_binary(path.as_bytes())).into_owned()
}

/// Decode percent-escapes, drop `;` path parameters, empty and `.` segments,
/// and resolve `..`, treating `\` as a separator. `None` when a `..` climbs
/// above the root.
fn lenient_router_segments(path: &str) -> Option<Vec<String>> {
    let decoded = percent_decode_lossy(path);
    let mut segments: Vec<String> = Vec::new();
    for segment in decoded.split(['/', '\\']) {
        match segment
            .split(';')
            .next()
            .unwrap_or_default()
        {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            segment => segments.push(segment.to_string()),
        }
    }
    Some(segments)
}

/// The upstream URLs at which this gateway fetches the surface's agent card: the
/// override path on the Target origin when `override_agent_card_location` is set,
/// otherwise the Target endpoint followed by `/.well-known/agent-card.json` and by
/// `/.well-known/agent.json`.
pub fn agent_card_urls(surface: &crate::config::agent_surface::AgentSurface) -> Vec<url::Url> {
    let endpoint = &surface.target.endpoint;
    let candidates = match surface
        .agent_card_location_path()
        .filter(|_| surface.override_agent_card_location())
    {
        Some(custom_path) => vec![crate::proxy::protocol_router::override_agent_card_url(endpoint, custom_path)],
        None => ["/.well-known/agent-card.json", "/.well-known/agent.json"]
            .into_iter()
            .map(|path| crate::proxy::protocol_router::join_endpoint_path(endpoint, path))
            .collect(),
    };
    candidates
        .iter()
        .filter_map(|candidate| url::Url::parse(candidate).ok())
        .collect()
}

/// Whether `destination` is exactly one of the surface's agent card URLs, the
/// only requests the gateway sends to its Target on its own behalf.
pub fn is_agent_card_url(
    surface: &crate::config::agent_surface::AgentSurface,
    destination: &str,
) -> bool {
    url::Url::parse(destination)
        .is_ok_and(|parsed| parsed.fragment().is_none() && agent_card_urls(surface).contains(&parsed))
}

/// Whether a request is the gateway's own card fetch: a `GET` whose upstream URL,
/// query included, is exactly one of the surface's agent card URLs.
pub fn is_gateway_card_fetch(
    surface: &crate::config::agent_surface::AgentSurface,
    method: &str,
    upstream_url: &str,
) -> bool {
    method.eq_ignore_ascii_case("GET") && is_agent_card_url(surface, upstream_url)
}

/// Whether a Target credential may travel to `destination`: one of the surface's
/// agent card URLs, or a URL on the Target endpoint's origin whose path stays under
/// the Target base path both as the URL parser resolves it and as lenient routers
/// resolve the raw and the decoded path. Unparseable input, or a `..` above the
/// root, is outside.
pub fn is_within_target_base(
    surface: &crate::config::agent_surface::AgentSurface,
    destination: &str,
) -> bool {
    if is_agent_card_url(surface, destination) {
        return true;
    }
    let Ok(parsed) = url::Url::parse(destination) else {
        return false;
    };
    let Ok(target) = url::Url::parse(&surface.target.endpoint) else {
        return false;
    };
    if parsed.origin() != target.origin() {
        return false;
    }
    let Some(base) = lenient_router_segments(target.path()) else {
        return false;
    };
    [
        lenient_router_segments(parsed.path()),
        lenient_router_segments(&percent_decode_lossy(parsed.path())),
        lenient_router_segments(raw_url_path(destination)),
    ]
    .iter()
    .all(|segments| {
        segments
            .as_deref()
            .is_some_and(|segments| segments.starts_with(&base))
    })
}

/// The path of a URL exactly as written, before the URL parser resolves any dot
/// segment: from the first `/` after the authority up to the query or fragment.
fn raw_url_path(url: &str) -> &str {
    let after_scheme = url
        .split_once("://")
        .map_or(url, |(_, rest)| rest);
    let path_and_rest = after_scheme
        .find('/')
        .map_or("/", |start| &after_scheme[start..]);
    path_and_rest
        .split(['?', '#'])
        .next()
        .unwrap_or("/")
}

/// Whether a request is a public discovery read that bypasses the request
/// gates: a `GET` or `HEAD` for a public path. A request with another method
/// whose path only ends like a discovery document, such as an MCP POST to
/// `{route}/agent.json`, still runs source auth, OPA and tool gating.
pub fn is_public_request(
    method: &str,
    path: &str,
) -> bool {
    (method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")) && is_public_path(path)
}

/// Whether a request to `surface` is a public discovery read, `route_tail` being
/// its path after the route and any `$alias`. An Access Point that declares
/// (`protected_resource`) publishes only its well-known card and UCP URLs, so
/// on it only a `GET` or `HEAD` of exactly one of those is public. Any other
/// Access Point follows [`is_public_request`].
pub fn is_public_surface_request(
    surface: &crate::config::agent_surface::AgentSurface,
    method: &str,
    route_tail: &str,
) -> bool {
    if !crate::source_auth::declaration::requests_declaration(surface) {
        return is_public_request(method, route_tail);
    }
    let tail = route_tail
        .split(['?', '#'])
        .next()
        .unwrap_or(route_tail);
    let tail = tail
        .strip_suffix('/')
        .unwrap_or(tail);
    (method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD"))
        && matches!(
            tail,
            "/.well-known/agent-card.json" | "/.well-known/agent.json" | "/.well-known/agent-card" | "/.well-known/ucp"
        )
}

/// Top-level paths owned by the dashboard SPA (www/default).
/// A channel prefix that shadows any of these would silently break the
/// dashboard, since channel routes take precedence over the SPA fallback
/// `ServeDir`. Keep in sync with the routes declared in
/// `www/default/src/pages/AuthenticatedApp.tsx`.
const SPA_RESERVED_TOP_LEVEL: &[&str] = &[
    "audit",
    "certificates",
    "connections",
    "connection-points",
    "credential-providers",
    "credentials",
    "dashboard",
    "delegation-vault",
    "departments",
    "gateways",
    "identities",
    "integrations",
    "logs",
    "mediators",
    "metrics",
    "notifications",
    "oidc-providers",
    "onboard",
    "x402payments",
    "policies",
    "profile",
    "proxies",
    "secrets",
    "settings",
    "surfaces",
    "system-metrics",
    "tasks",
    "trust-registries",
    "users",
];

/// Returns the first path segment of `prefix`, lowercased, or `None` if the
/// prefix is empty / root. E.g. `"/x402payments"` -> `Some("x402payments")`,
/// `"/svc/payments"` -> `Some("svc")`.
fn first_segment(prefix: &str) -> Option<String> {
    prefix
        .trim_start_matches('/')
        .split('/')
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
}

/// Validate that no channel / proxy / pipe prefix collides with a top-level
/// SPA route. Channel routes are merged into the same router as the SPA's
/// fallback `ServeDir`, and explicit channel routes win — a collision
/// silently breaks the dashboard page with a proxy 404.
///
/// Returns the list of conflicting `(prefix, spa_path)` pairs. Empty on success.
pub fn check_spa_route_collisions<'a, I>(prefixes: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut collisions = Vec::new();
    for prefix in prefixes {
        if let Some(seg) = first_segment(prefix)
            && SPA_RESERVED_TOP_LEVEL.contains(&seg.as_str())
        {
            collisions.push((prefix.to_string(), format!("/{}", seg)));
        }
    }
    collisions
}

/// Validate that no prefix lies at or below the protected resource metadata path.
/// Every inbound listener mounts the metadata routes itself and they take every
/// method on that path, so a route there could never be reached, and two routes
/// over one path would stop the listener from starting.
///
/// Returns the list of conflicting `(prefix, metadata_path)` pairs. Empty on success.
pub fn check_metadata_path_collisions<'a, I>(prefixes: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = &'a str>,
{
    prefixes
        .into_iter()
        .filter(|prefix| is_protected_resource_metadata_route(prefix))
        .map(|prefix| (prefix.to_string(), PROTECTED_RESOURCE_METADATA_PATH.to_string()))
        .collect()
}

/// Whether a stored surface's Access Point route may be mounted. A route at or under
/// the protected resource metadata path is logged and left unmounted, because the
/// metadata routes answer every request there.
pub fn surface_route_is_mountable(surface: &crate::config::agent_surface::AgentSurface) -> bool {
    let route = surface
        .access_point
        .route
        .as_str();
    if !is_protected_resource_metadata_route(route) {
        return true;
    }
    tracing::error!(
        surface_id = %surface.surface_id,
        route,
        "Surface route is at or under {PROTECTED_RESOURCE_METADATA_PATH}, so the surface is not mounted; change its route"
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface_with_target(
        endpoint: &str,
        agent_card_path: Option<&str>,
    ) -> crate::config::agent_surface::AgentSurface {
        serde_json::from_value(serde_json::json!({
            "name": "confined",
            "access_point": {
                "listen_address": "127.0.0.1:0",
                "route": "/agent",
                "protocol": "a2a",
                "agent_card_path": agent_card_path
            },
            "target": { "endpoint": endpoint }
        }))
        .expect("surface JSON")
    }

    #[test]
    fn only_the_metadata_path_and_paths_below_it_are_metadata_routes() {
        for route in [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/",
            "/.well-known/oauth-protected-resource/agent",
        ] {
            assert!(is_protected_resource_metadata_route(route), "{route}");
        }
        for route in [
            "/agent",
            "/.well-known/oauth-protected-resources",
            "/agent/.well-known/oauth-protected-resource",
            "/.well-known",
            "",
            "/",
        ] {
            assert!(!is_protected_resource_metadata_route(route), "{route}");
        }
    }

    #[test]
    fn only_a_route_with_a_dollar_or_its_encoding_holds_the_variant_separator() {
        for route in ["/smoke$dev", "/smoke%24dev", "/$"] {
            assert!(route_holds_variant_separator(route), "{route}");
        }
        for route in ["/smoke", "/smoke-dev/24", "/smoke%2F24"] {
            assert!(!route_holds_variant_separator(route), "{route}");
        }
    }

    #[test]
    fn test_agent_card_urls_follow_the_override_or_the_endpoint() {
        let default = surface_with_target("https://agent.example/api", None);
        assert_eq!(
            agent_card_urls(&default)
                .iter()
                .map(url::Url::as_str)
                .collect::<Vec<_>>(),
            vec![
                "https://agent.example/api/.well-known/agent-card.json",
                "https://agent.example/api/.well-known/agent.json"
            ]
        );
        let overridden = surface_with_target("https://agent.example/api", Some("cards/agent.json?v=2"));
        assert_eq!(
            agent_card_urls(&overridden)
                .iter()
                .map(url::Url::as_str)
                .collect::<Vec<_>>(),
            vec!["https://agent.example/cards/agent.json?v=2"]
        );
    }

    #[test]
    fn a_target_endpoint_without_a_scheme_yields_no_card_url_to_carry_a_credential() {
        let surface = surface_with_target("agent.example", Some("/card.json"));
        assert!(agent_card_urls(&surface).is_empty());
        assert!(!is_within_target_base(&surface, "https://agent.example/card.json"));
    }

    #[test]
    fn test_only_the_agent_card_urls_are_agent_card_urls() {
        let surface = surface_with_target("https://agent.example/api", None);
        for card in [
            "https://agent.example/api/.well-known/agent-card.json",
            "https://agent.example/api/.well-known/agent.json",
        ] {
            assert!(is_agent_card_url(&surface, card), "{card}");
        }
        for other in [
            "https://agent.example/api/admin/reports/discovery",
            "https://agent.example/api/x/.well-known/agent-card.json",
            "https://agent.example/api/.well-known/agent-card.json?x=1",
            "https://agent.example/api/.well-known/agent-card.json#x",
            "https://agent.example/api/.well-known/ucp",
            "https://other.example/api/.well-known/agent-card.json",
            "not a url",
        ] {
            assert!(!is_agent_card_url(&surface, other), "{other}");
        }
    }

    #[test]
    fn test_gateway_card_fetch_is_a_get_of_a_card_url() {
        let surface = surface_with_target("https://agent.example/api", None);
        let card = "https://agent.example/api/.well-known/agent-card.json";
        assert!(is_gateway_card_fetch(&surface, "GET", card));
        assert!(is_gateway_card_fetch(&surface, "get", card));
        for method in ["HEAD", "POST", "DELETE"] {
            assert!(!is_gateway_card_fetch(&surface, method, card), "{method}");
        }
        assert!(!is_gateway_card_fetch(&surface, "GET", &format!("{card}?x=1")));
        assert!(!is_gateway_card_fetch(&surface, "GET", "https://agent.example/api/discovery"));
    }

    #[test]
    fn test_paths_under_the_target_base_keep_the_credential() {
        let surface = surface_with_target("https://agent.example/api/", None);
        for destination in [
            "https://agent.example/api",
            "https://agent.example/api/",
            "https://agent.example/api/v1/message:send?x=1",
            "https://agent.example/api/./tasks",
            "https://agent.example/api/a/../tasks",
            "https://agent.example/api/.well-known/agent-card.json",
        ] {
            assert!(is_within_target_base(&surface, destination), "{destination}");
        }
    }

    #[test]
    fn test_paths_that_climb_out_of_the_target_base_lose_the_credential() {
        let surface = surface_with_target("https://agent.example/api", None);
        for destination in [
            "https://agent.example/api/../admin",
            "https://agent.example/api/%2e%2e/admin",
            "https://agent.example/api/%2E%2E/admin",
            "https://agent.example/api/..%2fadmin",
            "https://agent.example/api/..%5cadmin",
            "https://agent.example/api/..;/admin",
            "https://agent.example/api/%252e%252e/admin",
            "https://agent.example/admin",
            "https://agent.example/apiary",
            "https://other.example/api/tasks",
            "http://agent.example/api/tasks",
            "https://agent.example:8443/api/tasks",
            "not a url",
        ] {
            assert!(!is_within_target_base(&surface, destination), "{destination}");
        }
    }

    #[test]
    fn test_root_target_refuses_only_a_climb_above_the_root() {
        let surface = surface_with_target("https://agent.example", None);
        assert!(is_within_target_base(&surface, "https://agent.example/anything/here"));
        assert!(!is_within_target_base(&surface, "https://agent.example/%2e%2e/etc"));
    }

    #[test]
    fn test_unparseable_target_endpoint_never_carries_the_credential() {
        let surface = surface_with_target("not a url", None);
        assert!(!is_within_target_base(&surface, "https://agent.example/api/tasks"));
    }

    #[test]
    fn test_target_base_that_climbs_above_the_root_never_carries_the_credential() {
        let surface = surface_with_target("https://agent.example/a/..%2f..%2fb", None);
        assert!(!is_within_target_base(&surface, "https://agent.example/b/tasks"));
    }

    #[test]
    fn test_override_card_url_outside_the_base_keeps_the_credential_only_exactly() {
        let surface = surface_with_target("https://agent.example/api", Some("/card.json"));
        assert!(is_within_target_base(&surface, "https://agent.example/card.json"));
        assert!(!is_within_target_base(&surface, "https://agent.example/card.json?x=1"));
        assert!(!is_within_target_base(&surface, "https://agent.example/card.json#frag"));
        assert!(!is_within_target_base(&surface, "https://agent.example/other.json"));
    }

    #[test]
    fn only_a_get_or_head_for_a_public_path_is_a_public_request() {
        for method in ["GET", "HEAD", "get"] {
            assert!(is_public_request(method, "/surface/agent.json"), "{method}");
        }
        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            assert!(
                !is_public_request(method, "/surface/agent.json"),
                "a {method} that only ends like a discovery document must still be gated"
            );
        }
        assert!(!is_public_request("GET", "/surface/tools"));
    }

    #[test]
    fn a_declaring_access_point_publishes_only_its_exact_card_and_ucp_urls() {
        use crate::protocols::protected_resource::fixtures::{discovery_surface, jwt_bearer_method};
        let declaring = discovery_surface(
            jwt_bearer_method(),
            Some(serde_json::json!({"resource": "https://gateway.example/mcp/alpha", "scopes": ["tools"]})),
        );
        assert!(crate::source_auth::declaration::requests_declaration(&declaring));
        for (method, tail) in [
            ("GET", "/.well-known/agent-card.json"),
            ("HEAD", "/.well-known/agent.json"),
            ("GET", "/.well-known/agent-card"),
            ("GET", "/.well-known/ucp"),
            ("get", "/.well-known/agent-card.json/?x=1"),
        ] {
            assert!(is_public_surface_request(&declaring, method, tail), "{method} {tail}");
        }
        for (method, tail) in [
            ("GET", "/agent.json"),
            ("GET", "/agent-card.json"),
            ("GET", "/tasks/discovery"),
            ("GET", "/x/.well-known/ucp"),
            ("GET", "/x/.well-known/agent-card.json"),
            ("POST", "/.well-known/agent-card.json"),
            ("GET", "/"),
        ] {
            assert!(!is_public_surface_request(&declaring, method, tail), "{method} {tail}");
        }
    }

    #[test]
    fn an_access_point_that_does_not_declare_keeps_the_suffix_rule() {
        use crate::protocols::protected_resource::fixtures::{discovery_surface, jwt_bearer_method};
        let plain = discovery_surface(jwt_bearer_method(), None);
        assert!(!crate::source_auth::declaration::requests_declaration(&plain));
        for method in ["GET", "HEAD", "POST"] {
            for tail in [
                "/agent.json",
                "/agent-card.json",
                "/tasks/discovery",
                "/x/.well-known/ucp",
                "/x/.well-known/agent-card",
                "/.well-known/agent-card.json",
                "/tools",
            ] {
                assert_eq!(
                    is_public_surface_request(&plain, method, tail),
                    is_public_request(method, tail),
                    "{method} {tail}"
                );
            }
        }
    }

    const ROOT_TARGET: &str = "http://target.example";
    const BASE_TARGET: &str = "http://target.example/base/";

    fn is_card(path: &str) -> bool {
        is_rest_extended_agent_card_request("GET", ROOT_TARGET, path)
    }

    #[test]
    fn rest_extended_agent_card_request_matches_both_eras_for_any_method_but_head_and_options() {
        for path in ["/extendedAgentCard", "/v1/card", "/extendedAgentCard/", "v1/card", "extendedAgentCard"] {
            for method in ["GET", "get", "POST", "PUT", "DELETE"] {
                assert!(is_rest_extended_agent_card_request(method, ROOT_TARGET, path), "{method} {path}");
            }
            for method in ["HEAD", "OPTIONS", "options"] {
                assert!(!is_rest_extended_agent_card_request(method, ROOT_TARGET, path), "{method} {path}");
            }
        }
        for path in [
            "/extendedAgentCard/extra",
            "/foo/v1/card",
            "/payments/v1/card",
            "/card",
            "/v1/cards",
            "/.well-known/agent-card.json",
            "/rpc",
            "/",
        ] {
            assert!(!is_card(path), "{path}");
        }
    }

    #[test]
    fn rest_extended_agent_card_request_matches_tenant_scoped_extended_card_paths() {
        for path in [
            "/acme/extendedAgentCard",
            "/a/b/extendedAgentCard/",
            "/x/./extendedAgentCard",
            "/foo:bar/extendedAgentCard",
        ] {
            assert!(is_card(path), "{path}");
        }
        assert!(!is_card("/acme/v1/card"));
    }

    #[test]
    fn rest_extended_agent_card_request_matches_non_canonical_spellings_of_the_card_path() {
        for path in [
            "/./extendedAgentCard",
            "/x/../v1/card",
            "/x/%2e%2e/extendedAgentCard",
            "/%2E/v1/card",
            "/../extendedAgentCard",
            "/extended%41gentCard",
            "/v1%2Fcard",
            "//extendedAgentCard",
            "/extendedagentcard",
            "/EXTENDEDAGENTCARD",
            "/V1/Card",
            "/foo:bar/../extendedAgentCard",
            "/x/foo:bar/../../v1/card",
            "/extendedAgentCard;x=1",
            "/v1;a=b/card",
            "/v1/card;jsessionid=abc",
            "/v1//card",
            "/v1/%2F/card",
            "/x/..;/extendedAgentCard",
            "/x/y//../../v1/card",
            "/v1//../card",
            "/x\\..\\extendedAgentCard",
        ] {
            assert!(is_card(path), "{path}");
        }
        for path in ["/payments/%2e/v1/card", "/x/y/../v1/card", "/payments;x=1/v1/card", "/x//v1/card"] {
            assert!(!is_card(path), "{path}");
        }
    }

    #[test]
    fn rest_extended_agent_card_request_resolves_against_the_target_base_path() {
        for path in ["/v1/card", "/extendedAgentCard", "/x/../v1/card"] {
            assert!(is_rest_extended_agent_card_request("GET", BASE_TARGET, path), "{path}");
        }
        for path in ["/rpc", "/", "/v1/cards", "/x/v1/card"] {
            assert!(!is_rest_extended_agent_card_request("GET", BASE_TARGET, path), "{path}");
        }
    }

    #[test]
    fn rest_extended_agent_card_request_treats_a_climb_out_of_the_target_base_as_a_card() {
        for path in [
            "/../base/extendedAgentCard",
            "/%2e%2e/base/extendedAgentCard",
            "/../base/./extendedAgentCard",
            "/x/../../base/v1/card",
            "/..;/base/v1/card",
            "/../other/rpc",
        ] {
            assert!(is_rest_extended_agent_card_request("GET", BASE_TARGET, path), "{path}");
        }
    }

    #[test]
    fn rest_extended_agent_card_request_ignores_the_base_of_non_http_targets() {
        assert!(is_rest_extended_agent_card_request("GET", "fabric://peer/surface", "/v1/card"));
        assert!(!is_rest_extended_agent_card_request("GET", "fabric://peer/surface", "/surface/rpc"));
        assert!(!is_rest_extended_agent_card_request("GET", "fabric://peer/surface", "/x/../rpc"));
    }

    #[test]
    fn rest_extended_agent_card_request_treats_a_climb_above_the_root_as_a_card() {
        for target in ["fabric://peer/surface", ROOT_TARGET, BASE_TARGET] {
            for path in [
                "/../base/v1/card",
                "/x/../../base/v1/card",
                "/%2e%2e/base/v1/card",
                "/..;/base/v1/card",
                "/..\\base\\v1\\card",
                "/../rpc",
            ] {
                assert!(is_rest_extended_agent_card_request("GET", target, path), "{target} {path}");
            }
        }
    }

    #[test]
    fn well_known_agent_card_path_matches_only_well_known_card_documents() {
        assert!(is_well_known_agent_card_path("/surface/.well-known/agent-card.json"));
        assert!(is_well_known_agent_card_path("/.well-known/agent.json"));
        for path in [
            "/surface/agent-card.json",
            "/surface/agent.json",
            "/surface/.well-known/agent-card",
            "/surface/.well-known/ucp",
            "/surface/discovery",
            "/surface/rpc",
        ] {
            assert!(!is_well_known_agent_card_path(path), "{path}");
        }
    }

    #[test]
    fn public_path_matches_the_documented_discovery_endpoints() {
        for path in [
            "/payments/garlic/station/discovery",
            "/discovery",
            "/agents/copilot-worker/discovery",
            "/payments/garlic/station/discovery/",
            "/surface/.well-known/agent-card.json",
            "/surface/.well-known/agent.json",
            "/surface/agent-card.json",
            "/surface/agent.json",
            "/.well-known/ucp",
            "/surface/.well-known/ucp",
            "/surface/.well-known/agent-card",
        ] {
            assert!(is_public_path(path), "{path} is a discovery endpoint and must stay public");
        }
    }

    /// The predicate used to be a substring match, so any caller could switch off
    /// source authentication, OPA and the appliance-wide policies by putting `/discovery`
    /// anywhere in the request path.
    #[test]
    fn public_path_rejects_paths_that_merely_contain_a_discovery_segment() {
        for path in [
            "/payments/garlic/station/not-really/discovery/x",
            "/discovery/../../admin",
            "/api/v1/secrets?x=/discovery",
            "/discovery-api/orders",
            "/v1/discoveryx",
            "/.well-known/ucp/../admin",
            "/agent.json/../../v1/secrets",
            "/surface/.well-known/agent-card/evil",
        ] {
            assert!(!is_public_path(path), "{path} is not a discovery endpoint and must not bypass inbound controls");
        }
    }

    #[test]
    fn collision_detects_exact_match() {
        let hits = check_spa_route_collisions(["/x402payments"]);
        assert_eq!(hits, vec![("/x402payments".to_string(), "/x402payments".to_string())]);
    }

    #[test]
    fn collision_detects_nested_under_reserved() {
        let hits = check_spa_route_collisions(["/x402payments/sub"]);
        assert_eq!(hits, vec![("/x402payments/sub".to_string(), "/x402payments".to_string())]);
    }

    #[test]
    fn collision_ignores_non_reserved_prefix() {
        assert!(check_spa_route_collisions(["/payments", "/helpdesk", "/foo"]).is_empty());
    }

    #[test]
    fn collision_ignores_root_and_empty() {
        assert!(check_spa_route_collisions(["/", ""]).is_empty());
    }

    #[test]
    fn collision_is_case_insensitive() {
        let hits = check_spa_route_collisions(["/X402Payments"]);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn spa_collision_ignores_the_metadata_path() {
        assert!(check_spa_route_collisions(["/.well-known/oauth-protected-resource/agent"]).is_empty());
    }

    #[test]
    fn collision_detects_the_protected_resource_metadata_path() {
        let hits = check_metadata_path_collisions([
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/agent",
            "/.well-known/agent",
            "/.well-known",
            "/x402payments",
            "",
        ]);
        assert_eq!(
            hits,
            vec![
                ("/.well-known/oauth-protected-resource".to_string(), PROTECTED_RESOURCE_METADATA_PATH.to_string()),
                (
                    "/.well-known/oauth-protected-resource/agent".to_string(),
                    PROTECTED_RESOURCE_METADATA_PATH.to_string()
                ),
            ]
        );
    }

    #[test]
    fn only_a_surface_outside_the_metadata_path_is_mountable() {
        let at = |route: &str| {
            let mut surface = surface_with_target("https://agent.example/api", None);
            surface.access_point.route = route.to_string();
            surface
        };
        for route in ["/agent", "/.well-known/agent", "/"] {
            assert!(surface_route_is_mountable(&at(route)), "{route}");
        }
        for route in ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/agent"] {
            assert!(!surface_route_is_mountable(&at(route)), "{route}");
        }
    }

    #[test]
    fn metadata_collision_ignores_unrelated_prefixes() {
        assert!(check_metadata_path_collisions(["/agent", "/", "/.well-known/oauth-protected-resources"]).is_empty());
    }
}
