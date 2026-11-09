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

/// Whether a Target credential may go to `outbound_url` with `method`: the URL stays
/// under the Target base path ([`is_within_target_base`]), or a `GET` or `HEAD` goes to
/// the surface's configured agent card location on the Target's origin.
pub fn is_target_credential_destination(
    target_endpoint: &str,
    method: &str,
    outbound_url: &str,
    agent_card_location: Option<&str>,
) -> bool {
    is_within_target_base(target_endpoint, outbound_url)
        || (method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD"))
            && agent_card_location.is_some_and(|location| {
                let (Some(target), Ok(outbound)) =
                    (parse_target_endpoint(target_endpoint), url::Url::parse(outbound_url))
                else {
                    return false;
                };
                target
                    .join(&format!("/{}", location.trim_start_matches('/')))
                    .is_ok_and(|card| {
                        same_origin(&card, &outbound) && normalize_path(card.path()) == normalize_path(outbound.path())
                    })
            })
}

/// Whether `outbound_url` stays under the Target `target_endpoint`: the same
/// scheme, host and port (a default port equals an explicit one), and a path
/// equal to the Target's path or below it. Both paths are compared after
/// decoding percent-encoded unreserved characters (RFC 3986 section 2.3, never
/// `%2F`) and removing dot segments (RFC 3986 section 5.2.4). A Target with an
/// empty or `/` path allows every path. Below a non-root base, a segment a
/// server could still resolve as `.` or `..` is refused ([`is_ambiguous_dot_segment`]).
/// The query and fragment are ignored, and a URL that cannot be parsed is refused.
pub fn is_within_target_base(
    target_endpoint: &str,
    outbound_url: &str,
) -> bool {
    let (Some(target), Ok(outbound)) = (parse_target_endpoint(target_endpoint), url::Url::parse(outbound_url)) else {
        return false;
    };
    if !same_origin(&target, &outbound) {
        return false;
    }
    let base = normalize_path(target.path());
    let base = base.trim_end_matches('/');
    if base.is_empty() {
        return true;
    }
    let path = normalize_path(outbound.path());
    path.strip_prefix(base)
        .is_some_and(|rest| {
            (rest.is_empty() || rest.starts_with('/'))
                && !rest
                    .split('/')
                    .any(is_ambiguous_dot_segment)
        })
}

/// Whether a normalised path segment is one a server could still resolve as `.`
/// or `..`: a dot segment with `;` parameters (`..;x`), a dot reference beside an
/// encoded slash or backslash (`..%2Fx`, `%5C..`), or the same spelled so that a
/// server decoding more than once, or decoding `%u`, overlong UTF-8 or fullwidth
/// forms, turns it into one (`%252E`, `..%252F`, `..%3B`, `%C0%AE`, `%E2%80%A5`).
/// A segment with a `%u` escape or `%00`, or still holding `%25` after three
/// decoding rounds, is refused outright, which keeps the work linear in the
/// segment's length.
fn is_ambiguous_dot_segment(segment: &str) -> bool {
    const DECODING_ROUNDS: usize = 3;
    const LOOKALIKES: [(&str, &str); 14] = [
        ("%C0%AE", "."),
        ("%E0%80%AE", "."),
        ("%EF%BC%8E", "."),
        ("%EF%B9%92", "."),
        ("%E2%80%A4", "."),
        ("%E2%80%A5", ".."),
        ("%2E", "."),
        ("%C0%AF", "/"),
        ("%EF%BC%8F", "/"),
        ("%EF%BC%BC", "/"),
        ("%2F", "/"),
        ("%5C", "/"),
        ("\\", "/"),
        ("%3B", ";"),
    ];
    if !segment.contains(['%', ';', '\\']) {
        return false;
    }
    let mut decoded = segment.to_ascii_uppercase();
    if decoded.contains("%U") || decoded.contains("%00") {
        return true;
    }
    for _ in 0..DECODING_ROUNDS {
        if !decoded.contains("%25") {
            break;
        }
        decoded = decoded.replace("%25", "%");
    }
    if decoded.contains("%25") {
        return true;
    }
    LOOKALIKES
        .iter()
        .fold(decoded, |path, (escape, plain)| path.replace(escape, plain))
        .split('/')
        .any(|part| {
            matches!(
                part.split(';')
                    .next()
                    .unwrap_or_default(),
                "." | ".."
            )
        })
}

/// Whether `path`, appended below a base path the gateway does not know (a peer
/// gateway's Target over Fabric), stays below that base by the rules of
/// [`is_within_target_base`].
pub fn appended_path_stays_below_base(path: &str) -> bool {
    is_within_target_base(
        "https://base.invalid/base",
        &format!("https://base.invalid/base/{}", path.trim_start_matches('/')),
    )
}

/// A Target endpoint without a scheme is read as `https://`, the scheme the protocol router
/// names for it; the router's forward URL keeps no scheme, so no request reaches it.
fn parse_target_endpoint(target_endpoint: &str) -> Option<url::Url> {
    if target_endpoint.contains("://") {
        url::Url::parse(target_endpoint).ok()
    } else {
        url::Url::parse(&format!("https://{target_endpoint}")).ok()
    }
}

fn same_origin(
    a: &url::Url,
    b: &url::Url,
) -> bool {
    a.scheme() == b.scheme() && a.host() == b.host() && a.port_or_known_default() == b.port_or_known_default()
}

fn normalize_path(path: &str) -> String {
    remove_dot_segments(&decode_unreserved(path))
}

/// Decode percent-encoded unreserved characters (RFC 3986 section 2.3) and
/// upper-case the hex digits of every other escape, so `%2F` stays encoded.
fn decode_unreserved(path: &str) -> String {
    let mut decoded = String::with_capacity(path.len());
    let mut index = 0;
    while index < path.len() {
        let escape = path[index..]
            .strip_prefix('%')
            .and_then(|rest| rest.get(..2))
            .filter(|hex| {
                hex.bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            })
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match escape {
            Some(byte) if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') => {
                decoded.push(char::from(byte));
                index += 3;
            }
            Some(byte) => {
                decoded.push_str(&format!("%{byte:02X}"));
                index += 3;
            }
            None => {
                let next = path[index..]
                    .chars()
                    .next()
                    .map_or(1, char::len_utf8);
                decoded.push_str(&path[index..index + next]);
                index += next;
            }
        }
    }
    decoded
}

/// Remove `.` and `..` segments as RFC 3986 section 5.2.4 does.
fn remove_dot_segments(path: &str) -> String {
    let mut input = path;
    let mut output = String::with_capacity(path.len());
    while !input.is_empty() {
        if let Some(rest) = input
            .strip_prefix("../")
            .or_else(|| input.strip_prefix("./"))
        {
            input = rest;
        } else if input.starts_with("/./") {
            input = &input[2..];
        } else if input == "/." {
            input = "/";
        } else if input.starts_with("/../") {
            input = &input[3..];
            output.truncate(output.rfind('/').unwrap_or(0));
        } else if input == "/.." {
            input = "/";
            output.truncate(output.rfind('/').unwrap_or(0));
        } else if input == "." || input == ".." {
            input = "";
        } else {
            let start = usize::from(input.starts_with('/'));
            let end = input[start..]
                .find('/')
                .map_or(input.len(), |offset| start + offset);
            output.push_str(&input[..end]);
            input = &input[end..];
        }
    }
    output
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
    "payments",
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
/// prefix is empty / root. E.g. `"/payments"` -> `Some("payments")`,
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

/// The fatal startup message for prefixes that shadow dashboard pages: each
/// offending prefix, the page it shadows, and how to fix it.
pub fn spa_collision_banner(collisions: &[(String, String)]) -> String {
    let detail = collisions
        .iter()
        .map(|(prefix, spa)| format!("    - prefix '{prefix}' shadows the dashboard page '{spa}'"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "\n\
         ============================================================\n\
         FATAL: Gateway configuration error\n\
         ============================================================\n\
         One or more channel/proxy prefixes collide with reserved\n\
         dashboard routes. Starting in this state would replace\n\
         dashboard pages with proxy 404s, so the server is exiting.\n\n\
         Collisions:\n{detail}\n\n\
         Fix: rename each offending prefix (a channel's `prefix`, or the\n\
         `prefix` of a proxy route, in your gateway.json) to one that is\n\
         not a dashboard page, e.g. '/svc/<name>', and restart. The\n\
         dashboard's Payments page owns '/payments', so a channel on\n\
         '/payments' must be renamed; clients that call it must use the\n\
         new prefix.\n\
         ============================================================\n"
    )
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
        assert!(check_spa_route_collisions(["/billing", "/helpdesk", "/foo", "/svc/payments"]).is_empty());
    }

    #[test]
    fn collision_detects_the_payments_page_and_its_legacy_redirect() {
        let hits = check_spa_route_collisions(["/payments", "/payments/v1/report", "/x402payments"]);
        assert_eq!(
            hits,
            vec![
                ("/payments".to_string(), "/payments".to_string()),
                ("/payments/v1/report".to_string(), "/payments".to_string()),
                ("/x402payments".to_string(), "/x402payments".to_string()),
            ]
        );
    }

    #[test]
    fn the_startup_error_names_each_prefix_the_page_it_shadows_and_the_rename() {
        let banner = spa_collision_banner(&check_spa_route_collisions(["/payments", "/svc/x", "/policies/v1"]));

        assert!(banner.contains("prefix '/payments' shadows the dashboard page '/payments'"), "{banner}");
        assert!(banner.contains("prefix '/policies/v1' shadows the dashboard page '/policies'"), "{banner}");
        assert!(!banner.contains("'/svc/x'"), "{banner}");
        assert!(banner.contains("rename each offending prefix"), "{banner}");
        assert!(banner.contains("'/payments' must be renamed"), "{banner}");
    }

    #[test]
    fn the_shipped_example_config_passes_the_dashboard_route_check() {
        let config = crate::config::NetworkConfig::load_from_file(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/config/examples/gateway.example.json"
        ))
        .expect("the shipped example config loads");
        assert!(!config.channels.is_empty(), "the example offers channel prefixes");
        assert_eq!(check_spa_route_collisions(config.proxy_prefixes()), Vec::<(String, String)>::new());
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

    const TARGET: &str = "https://api.example.com/base";

    #[test]
    fn target_base_allows_its_own_path_and_paths_below_it() {
        for url in [
            "https://api.example.com/base",
            "https://api.example.com/base/",
            "https://api.example.com/base/x",
            "https://api.example.com/base/x/y?next=/elsewhere",
            "https://API.example.com:443/base/x",
            "https://api.example.com/base/%7Euser",
            "https://api.example.com/base/x;v=1",
        ] {
            assert!(is_within_target_base(TARGET, url), "{url}");
        }
    }

    #[test]
    fn target_base_refuses_paths_that_climb_out_or_only_share_a_prefix() {
        for url in [
            "https://api.example.com/base/../x",
            "https://api.example.com/base/%2e%2e/x",
            "https://api.example.com/base/%2E%2E/x",
            "https://api.example.com/base/./../x",
            "https://api.example.com/base/..",
            "https://api.example.com/basex",
            "https://api.example.com/base;v=1/x",
            "https://api.example.com/",
            "https://api.example.com/other/base/x",
        ] {
            assert!(!is_within_target_base(TARGET, url), "{url}");
        }
    }

    #[test]
    fn target_base_refuses_another_host_port_or_scheme() {
        for url in [
            "https://evil.example.com/base/x",
            "https://api.example.com:8443/base/x",
            "http://api.example.com/base/x",
            "not a url",
        ] {
            assert!(!is_within_target_base(TARGET, url), "{url}");
        }
        assert!(is_within_target_base("http://127.0.0.1:8080/base", "http://127.0.0.1:8080/base/x"));
        assert!(!is_within_target_base("http://127.0.0.1:8080/base", "http://127.0.0.1:8081/base/x"));
    }

    #[test]
    fn target_base_keeps_an_encoded_slash_encoded() {
        assert!(is_within_target_base(TARGET, "https://api.example.com/base/%2Fx"));
        assert!(!is_within_target_base(TARGET, "https://api.example.com/base%2Fx"));
        assert!(!is_within_target_base(TARGET, "https://api.example.com/base%2fx"));
        assert_eq!(normalize_path("/base/%2fx/%41"), "/base/%2Fx/A");
    }

    #[test]
    fn target_base_with_a_trailing_slash_or_parameters_matches_its_own_spelling() {
        assert!(is_within_target_base("https://api.example.com/base/", "https://api.example.com/base/x"));
        assert!(is_within_target_base("https://api.example.com/base/", "https://api.example.com/base"));
        assert!(is_within_target_base("https://api.example.com/base;v=1", "https://api.example.com/base;v=1/x"));
        assert!(!is_within_target_base("https://api.example.com/base;v=1", "https://api.example.com/base/x"));
    }

    #[test]
    fn target_without_a_base_path_allows_every_path_on_its_origin() {
        for target in ["https://api.example.com", "https://api.example.com/", "api.example.com"] {
            assert!(is_within_target_base(target, "https://api.example.com/anything/../x"), "{target}");
            assert!(!is_within_target_base(target, "https://evil.example.com/x"), "{target}");
        }
    }

    #[test]
    fn an_appended_path_stays_below_an_unknown_base_unless_it_climbs_out() {
        for path in ["/", "/x", "/x/../y", "x/%2Fy"] {
            assert!(appended_path_stays_below_base(path), "{path}");
        }
        for path in ["/..", "/../x", "/%2e%2e/x", "/x/%2E%2E/%2e%2e/y", "/./../x"] {
            assert!(!appended_path_stays_below_base(path), "{path}");
        }
    }

    #[test]
    fn target_base_refuses_segments_a_server_could_still_resolve_as_dots() {
        for path in [
            "/base/..;/x",
            "/base/.;/x",
            "/base/..;x/y",
            "/base/%2e%2e;x/y",
            "/base/..%2Fx",
            "/base/..%2fx",
            "/base/..%5Cx",
            "/base/..%5cx",
            "/base/x%2F..%2Fy",
            "/base/%2F..",
            "/base/.%2Fx",
            "/base/%252e%252e/x",
            "/base/%252E%252E/x",
            "/base/x/%252e",
            "/base/..%252F..%252Fadmin",
            "/base/..%255C..%255Cadmin",
            "/base/..%25252Fadmin",
            "/base/..%3B/x",
            "/base/..%253Bx/y",
            "/base/%u002e%u002e/admin",
            "/base/%c0%ae%c0%ae/admin",
            "/base/%ef%bc%8e%ef%bc%8e/admin",
            "/base/..%00/admin",
            "/base/..%c0%afadmin",
            "/base/%25252525252e%25252525252e/admin",
            "/base/%E2%80%A5/admin",
            "/base/%E2%80%A4%E2%80%A4/admin",
            "/base/%EF%B9%92%EF%B9%92/admin",
        ] {
            let url = format!("https://api.example.com{path}");
            assert!(!is_within_target_base(TARGET, &url), "{path}");
        }
        assert!(!appended_path_stays_below_base("/..;/x"));
    }

    #[test]
    fn a_long_run_of_encoded_percent_signs_is_refused_in_linear_time() {
        let segment = format!("%{}", "25".repeat(30_000));
        let started = std::time::Instant::now();
        assert!(!is_within_target_base(TARGET, &format!("https://api.example.com/base/{segment}/x")));
        assert!(!appended_path_stays_below_base(&format!("/{segment}")));
        assert!(started.elapsed() < std::time::Duration::from_secs(1), "{:?}", started.elapsed());
    }

    #[test]
    fn target_base_still_allows_the_twins_of_ambiguous_dot_segments() {
        for path in [
            "/base/x;v=1",
            "/base/x;v=../y",
            "/base/%2Fx",
            "/base/a%2Fb",
            "/base/a%5Cb",
            "/base/...",
            "/base/..x",
            "/base/x..%2Fy",
            "/base/.well-known/agent-card.json",
            "/base/100%25",
            "/base/%2525",
            "/base/100%25UP",
            "/base/save%25user",
            "/base/a%2500b",
            "/base/caf%C3%A9",
        ] {
            let url = format!("https://api.example.com{path}");
            assert!(is_within_target_base(TARGET, &url), "{path}");
        }
        assert!(is_within_target_base("https://api.example.com/", "https://api.example.com/..;/x"));
        assert!(is_within_target_base("https://api.example.com", "https://api.example.com/..%2Fx"));
    }

    #[test]
    fn dot_segments_are_removed_after_decoding_unreserved_characters() {
        assert_eq!(normalize_path("/base/%2e%2e/x"), "/x");
        assert_eq!(normalize_path("/base/%2E%2e/x"), "/x");
        assert_eq!(normalize_path("/base/.%2e/x"), "/x");
        assert_eq!(normalize_path("/base/./y/../x"), "/base/x");
        assert_eq!(normalize_path("/../../x"), "/x");
        assert_eq!(normalize_path("/base/%zz/%"), "/base/%zz/%");
        assert_eq!(normalize_path("/base/%+1"), "/base/%+1");
        assert_eq!(normalize_path("/caf\u{e9}/%c3%a9"), "/caf\u{e9}/%C3%A9");
    }

    #[test]
    fn the_configured_agent_card_location_on_the_target_origin_may_carry_the_credential() {
        let card = "https://api.example.com/.well-known/agent-card.json";
        assert!(!is_within_target_base(TARGET, card));
        assert!(is_target_credential_destination(TARGET, "GET", card, Some("/.well-known/agent-card.json")));
        assert!(is_target_credential_destination(TARGET, "GET", card, Some(".well-known/agent-card.json")));
        assert!(!is_target_credential_destination(TARGET, "GET", card, None));
        assert!(!is_target_credential_destination(TARGET, "GET", card, Some("/.well-known/agent.json")));
        assert!(!is_target_credential_destination(
            TARGET,
            "GET",
            "https://evil.example.com/.well-known/agent-card.json",
            Some("/.well-known/agent-card.json")
        ));
        assert!(is_target_credential_destination(TARGET, "GET", "https://api.example.com/base/x", None));
        assert!(is_target_credential_destination(TARGET, "head", card, Some("/.well-known/agent-card.json")));
        for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
            assert!(
                !is_target_credential_destination(TARGET, method, card, Some("/.well-known/agent-card.json")),
                "{method}"
            );
            assert!(
                is_target_credential_destination(TARGET, method, "https://api.example.com/base/x", None),
                "{method}"
            );
        }
    }
}
