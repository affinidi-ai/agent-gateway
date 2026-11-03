//! Shared path utilities for the proxy module.
//!
//! Defines which request paths are publicly accessible and must bypass all
//! authentication gates (OIDC, Trust Registry validation, etc.) regardless
//! of channel configuration.

/// The discovery documents a route serves, relative to its root.
const DISCOVERY_DOCUMENTS: &[&str] = &[
    ".well-known/agent-card.json",
    ".well-known/agent.json",
    "agent-card.json",
    "agent.json",
    ".well-known/ucp",
    ".well-known/agent-card",
    "discovery",
];

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

    DISCOVERY_DOCUMENTS
        .iter()
        .any(|document| {
            path.strip_suffix(document)
                .is_some_and(|prefix| prefix.ends_with('/'))
        })
}

/// Whether a request through a Transit Point is a public discovery read: a
/// `GET` or `HEAD` whose path below the Transit Point, which is the path its
/// target receives below the target endpoint, is exactly a discovery document.
/// Only that spelling counts, with at most one trailing slash: a document below
/// another segment, such as `admin/discovery`, or a path with percent-escapes,
/// `;` parameters, `\` or dot segments is not a discovery read, whatever the
/// target's router resolves it to.
pub fn is_transit_discovery_request(
    method: &str,
    transit_relative_path: &str,
) -> bool {
    let path = transit_relative_path.trim_start_matches('/');
    let path = path
        .strip_suffix('/')
        .unwrap_or(path);
    (method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")) && DISCOVERY_DOCUMENTS.contains(&path)
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn a_transit_discovery_request_is_a_get_or_head_of_a_discovery_document_at_the_transit_point_root() {
        for path in [
            ".well-known/agent-card.json",
            "/.well-known/agent.json",
            "agent-card.json",
            "agent.json",
            ".well-known/ucp",
            ".well-known/agent-card",
            "discovery",
            "discovery/",
        ] {
            for method in ["GET", "HEAD", "get"] {
                assert!(is_transit_discovery_request(method, path), "{method} {path}");
            }
            for method in ["POST", "PUT", "DELETE", "OPTIONS"] {
                assert!(!is_transit_discovery_request(method, path), "{method} {path}");
            }
        }
    }

    #[test]
    fn a_transit_discovery_request_is_never_a_document_below_the_root_or_a_non_canonical_spelling() {
        for path in [
            "",
            "admin/discovery",
            "x/admin/discovery",
            "tools/agent.json",
            "admin/.well-known/agent-card.json",
            "discovery/x",
            "discovery//",
            "Discovery",
            "%64iscovery",
            "admin%2Fdiscovery",
            "admin%2f..%2fdiscovery",
            "admin/../discovery",
            "./discovery",
            "discovery;x=1",
            "admin;/discovery",
            "admin\\discovery",
            ".well-known/ucp/../../admin",
            ".well-known%2Fagent-card.json",
        ] {
            assert!(!is_transit_discovery_request("GET", path), "{path}");
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
}
