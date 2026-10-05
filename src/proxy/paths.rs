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

    path.ends_with("/.well-known/agent-card.json")
        || path.ends_with("/.well-known/agent.json")
        || path.ends_with("/agent-card.json")
        || path.ends_with("/agent.json")
        || path.ends_with("/.well-known/ucp")
        || path.ends_with("/.well-known/agent-card")
        || path.ends_with("/discovery")
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
        assert!(check_spa_route_collisions(["/payments", "/cats", "/foo"]).is_empty());
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
