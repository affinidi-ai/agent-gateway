//! The paths `gateway.json` claims on an inbound listener, and whether one of
//! them serves a surface route.

use super::agent_surface::{AgentSurface, SurfaceStatus};
use super::network::{NetworkConfig, RouteType};

/// The paths an entry's router registrations match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// The prefix itself only: a `redirect` route.
    Prefix,
    /// Only the paths below the prefix (`{prefix}/{*path}`): a `proxy` route or
    /// an MCP proxy prefix.
    Below,
    /// The prefix and every path below it.
    PrefixAndBelow,
}

/// A path prefix one `gateway.json` entry serves.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteClaim {
    prefix: String,
    owner: String,
    serves_surfaces: bool,
    reach: Reach,
}

impl RouteClaim {
    fn serves(
        &self,
        route: &str,
    ) -> bool {
        let below = match self.prefix.as_str() {
            "/" => route != "/",
            prefix => route
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/')),
        };
        match self.reach {
            Reach::Prefix => route == self.prefix,
            Reach::Below => below,
            Reach::PrefixAndBelow => route == self.prefix || below,
        }
    }
}

/// `route` as the inbound router matches it: with a leading `/` and without a
/// trailing one; `/` for an empty route.
pub fn normalize_route(route: &str) -> String {
    let trimmed = route.trim_end_matches('/');
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

const ROUTE_PUNCTUATION: &str = "-._~!&'()*+,;=:@";

/// Refuse an Access Point route that is not a plain path. A `$` or `%` would
/// let the route spell another surface's variant URL (`/route$alias`), and an
/// empty, `.` or `..` segment would make it longer than the route the inbound
/// router matches, which is how it ranks surfaces.
pub fn check_surface_route_syntax(route: &str) -> Result<(), String> {
    let plain_segments = route == "/"
        || route
            .split('/')
            .skip(1)
            .all(|segment| !matches!(segment, "" | "." | ".."));
    let plain_characters = route
        .chars()
        .all(|c| c == '/' || c.is_ascii_alphanumeric() || ROUTE_PUNCTUATION.contains(c));
    if route.starts_with('/') && plain_segments && plain_characters {
        Ok(())
    } else {
        Err(format!(
            "access_point.route '{route}' must be a plain path: segments of letters, digits and \
             {ROUTE_PUNCTUATION}, none of them empty, '.' or '..'"
        ))
    }
}

impl NetworkConfig {
    /// Every path prefix this configuration serves, with its owner. The static
    /// fallback serves whatever no other entry does, and the identity API,
    /// onboarding, static and connection point routes at `/` serve only their
    /// own paths there, so none of them claims a prefix.
    fn route_claims(&self) -> Vec<RouteClaim> {
        let channels = self
            .channels
            .iter()
            .map(|channel| RouteClaim {
                prefix: normalize_route(&channel.prefix),
                owner: format!("channel '{}'", channel.id),
                serves_surfaces: true,
                reach: Reach::PrefixAndBelow,
            });
        let mcp_proxies = self
            .mcp_proxies
            .iter()
            .flatten()
            .map(|proxy| RouteClaim {
                prefix: normalize_route(&proxy.prefix),
                owner: format!("MCP proxy prefix '{}'", proxy.id),
                serves_surfaces: false,
                reach: Reach::Below,
            });
        let mut named_routes: Vec<_> = self.routes.iter().collect();
        named_routes.sort_by_key(|(name, _)| name.as_str());
        let routes = named_routes
            .into_iter()
            .filter(|(_, route)| !(route.route_type == RouteType::Static && route.fallback))
            .map(|(name, route)| {
                let (serves_surfaces, reach) = match route.route_type {
                    RouteType::Proxy => (true, Reach::Below),
                    RouteType::Redirect => (false, Reach::Prefix),
                    RouteType::IdentityApi | RouteType::Onboarding | RouteType::Static | RouteType::ConnectionPoint => {
                        (false, Reach::PrefixAndBelow)
                    }
                };
                RouteClaim {
                    prefix: normalize_route(&route.prefix),
                    owner: format!("route '{name}' ({})", route.route_type.as_str()),
                    serves_surfaces,
                    reach,
                }
            })
            .filter(|claim| claim.prefix != "/" || claim.serves_surfaces || claim.reach == Reach::Prefix);
        channels
            .chain(mcp_proxies)
            .chain(routes)
            .collect()
    }

    /// Pairs of entries that claim the same prefix. The inbound router cannot
    /// serve one path twice: it refuses to start, or one entry hides the other.
    fn route_prefix_clashes(&self) -> Vec<(RouteClaim, RouteClaim)> {
        let claims = self.route_claims();
        claims
            .iter()
            .enumerate()
            .flat_map(|(index, first)| {
                claims[index + 1..]
                    .iter()
                    .filter(|second| second.prefix == first.prefix)
                    .map(|second| (first.clone(), second.clone()))
            })
            .collect()
    }

    /// Refuse a configuration in which two entries claim the same prefix,
    /// naming each pair, rather than let the inbound router fail to build.
    pub(super) fn validate_route_prefixes(&self) -> anyhow::Result<()> {
        let clashes = self.route_prefix_clashes();
        if clashes.is_empty() {
            return Ok(());
        }
        let detail = clashes
            .iter()
            .map(|(first, second)| format!("  - '{}': {} and {}", first.prefix, first.owner, second.owner))
            .collect::<Vec<_>>()
            .join("\n");
        anyhow::bail!(
            "gateway.json: these entries use the same path prefix, which the gateway cannot serve twice:\n{detail}\n\
             Give each entry its own prefix."
        )
    }

    /// Refuse a surface route callers cannot reach.
    pub fn check_surface_route(
        &self,
        route: &str,
    ) -> Result<(), String> {
        check_route_against(&self.route_claims(), route)
    }

    /// Each active surface callers cannot reach by its route, with the reason.
    pub fn unreachable_surfaces<'a>(
        &self,
        surfaces: &'a [AgentSurface],
    ) -> Vec<(&'a AgentSurface, String)> {
        let claims = self.route_claims();
        surfaces
            .iter()
            .filter(|surface| surface.status != SurfaceStatus::Disabled)
            .filter_map(|surface| {
                check_route_against(&claims, &surface.access_point.route)
                    .err()
                    .map(|reason| (surface, reason))
            })
            .collect()
    }
}

/// The entry with the longest prefix that serves a path gets its requests, so
/// a surface prefix must serve the route and no more specific entry may.
fn check_route_against(
    claims: &[RouteClaim],
    route: &str,
) -> Result<(), String> {
    let route = normalize_route(route);
    let surface_prefixes: Vec<&str> = claims
        .iter()
        .filter(|claim| claim.serves_surfaces)
        .map(|claim| claim.prefix.as_str())
        .collect();
    let advice = if surface_prefixes.is_empty() {
        "gateway.json declares no surface prefixes, so no surface can be reached by its route.".to_string()
    } else {
        format!("Choose a route under one of: {}.", surface_prefixes.join(", "))
    };
    match claims
        .iter()
        .filter(|claim| claim.serves(&route))
        .max_by_key(|claim| claim.prefix.len())
    {
        Some(claim) if claim.serves_surfaces => Ok(()),
        Some(claim) => Err(format!(
            "access_point.route '{route}' is served by {}, so callers cannot reach the surface there. {advice}",
            claim.owner
        )),
        None => Err(format!(
            "access_point.route '{route}' is not served by any surface prefix, so callers cannot reach the \
             surface. {advice}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(edit: impl FnOnce(&mut serde_json::Value)) -> NetworkConfig {
        let mut value = serde_json::json!({
            "did": { "domain": "test.local" },
            "webauthn": { "rp_id": "localhost", "external_origin": "https://localhost" },
            "integration": { "types": [], "categories": [] },
            "listeners": [],
            "channels": [{ "id": "agents", "name": "Agents", "prefix": "/agents" }],
            "mcp_proxies": [{ "id": "mcp", "name": "mcp", "prefix": "/mcp" }],
            "routes": {
                "api": { "type": "identity_api", "prefix": "/api" },
                "onboarding": { "type": "onboarding", "prefix": "/" },
                "dashboard": { "type": "static", "prefix": "/", "path": "www", "fallback": true },
                "avatars": { "type": "static", "prefix": "/avatars", "path": "avatars" }
            },
        });
        edit(&mut value);
        serde_json::from_value(value).expect("network config should deserialize")
    }

    fn add_route(
        value: &mut serde_json::Value,
        name: &str,
        route: serde_json::Value,
    ) {
        value["routes"][name] = route;
    }

    fn add_channel(
        value: &mut serde_json::Value,
        id: &str,
        prefix: &str,
    ) {
        value["channels"]
            .as_array_mut()
            .expect("channels")
            .push(serde_json::json!({ "id": id, "name": id, "prefix": prefix }));
    }

    fn docs_redirect() -> serde_json::Value {
        serde_json::json!({ "type": "redirect", "prefix": "/agents/docs", "target": "https://docs.example" })
    }

    fn refusal(
        config: &NetworkConfig,
        route: &str,
    ) -> String {
        config
            .check_surface_route(route)
            .expect_err(route)
    }

    #[test]
    fn a_route_is_normalized_the_way_the_inbound_router_matches_it() {
        assert_eq!(normalize_route("/agents/foo/"), "/agents/foo");
        assert_eq!(normalize_route("agents/foo"), "/agents/foo");
        assert_eq!(normalize_route("agents/foo/"), "/agents/foo");
        assert_eq!(normalize_route("/agents/foo//"), "/agents/foo");
        assert_eq!(normalize_route("/"), "/");
        assert_eq!(normalize_route(""), "/");
    }

    #[test]
    fn claims_name_each_entry_and_skip_the_root_routes_and_the_fallback() {
        let claims = config(|value| {
            add_route(value, "svc", serde_json::json!({ "type": "proxy", "prefix": "/svc/" }));
            add_route(value, "docs", docs_redirect());
        })
        .route_claims();

        let summary: Vec<(&str, &str, bool, Reach)> = claims
            .iter()
            .map(|claim| (claim.prefix.as_str(), claim.owner.as_str(), claim.serves_surfaces, claim.reach))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("/agents", "channel 'agents'", true, Reach::PrefixAndBelow),
                ("/mcp", "MCP proxy prefix 'mcp'", false, Reach::Below),
                ("/api", "route 'api' (identity_api)", false, Reach::PrefixAndBelow),
                ("/avatars", "route 'avatars' (static)", false, Reach::PrefixAndBelow),
                ("/agents/docs", "route 'docs' (redirect)", false, Reach::Prefix),
                ("/svc", "route 'svc' (proxy)", true, Reach::Below),
            ]
        );
    }

    #[test]
    fn distinct_prefixes_do_not_clash() {
        assert!(
            config(|_| {})
                .route_prefix_clashes()
                .is_empty()
        );
    }

    #[test]
    fn a_channel_and_a_static_route_on_one_prefix_clash() {
        let clashes = config(|value| add_channel(value, "files", "/avatars/")).route_prefix_clashes();

        assert_eq!(clashes.len(), 1, "{clashes:?}");
        let (first, second) = &clashes[0];
        assert_eq!(first.prefix, "/avatars");
        assert_eq!((first.owner.as_str(), second.owner.as_str()), ("channel 'files'", "route 'avatars' (static)"));
    }

    #[test]
    fn a_channel_and_an_mcp_proxy_prefix_on_one_prefix_clash() {
        let clashes = config(|value| add_channel(value, "tools", "/mcp")).route_prefix_clashes();

        assert_eq!(clashes.len(), 1, "{clashes:?}");
        assert_eq!(
            (clashes[0].0.owner.as_str(), clashes[0].1.owner.as_str()),
            ("channel 'tools'", "MCP proxy prefix 'mcp'")
        );
    }

    #[test]
    fn a_route_below_another_prefix_does_not_clash_with_it() {
        let clashes = config(|value| {
            add_channel(value, "nested", "/api/agents");
            add_route(value, "docs", docs_redirect());
        })
        .route_prefix_clashes();

        assert!(clashes.is_empty(), "{clashes:?}");
    }

    #[test]
    fn a_route_at_or_below_a_channel_prefix_is_reachable() {
        let config = config(|_| {});

        assert_eq!(config.check_surface_route("/agents"), Ok(()));
        assert_eq!(config.check_surface_route("/agents/foo"), Ok(()));
        assert_eq!(config.check_surface_route("/agents/foo/"), Ok(()));
    }

    #[test]
    fn a_route_outside_every_surface_prefix_is_unreachable() {
        let config = config(|_| {});

        for route in ["/foo", "/agentsfoo", "/"] {
            let reason = refusal(&config, route);
            assert!(reason.contains("is not served by any surface prefix"), "{reason}");
            assert!(reason.contains("under one of: /agents"), "{reason}");
        }
    }

    #[test]
    fn a_route_on_a_path_another_entry_serves_is_unreachable_and_names_it() {
        let config = config(|value| add_route(value, "docs", docs_redirect()));

        for (route, owner) in [
            ("/api/foo", "route 'api' (identity_api)"),
            ("/mcp/foo", "MCP proxy prefix 'mcp'"),
            ("/avatars", "route 'avatars' (static)"),
            ("/agents/docs", "route 'docs' (redirect)"),
            ("/agents/docs/", "route 'docs' (redirect)"),
        ] {
            let reason = refusal(&config, route);
            assert!(reason.contains(&format!("is served by {owner}")), "{route}: {reason}");
            assert!(reason.contains("under one of: /agents"), "{route}: {reason}");
        }
    }

    #[test]
    fn a_redirect_serves_its_exact_path_only() {
        let config = config(|value| add_route(value, "docs", docs_redirect()));

        assert_eq!(config.check_surface_route("/agents/docs/v2"), Ok(()));
        assert_eq!(config.check_surface_route("/agents/docsite"), Ok(()));
    }

    #[test]
    fn a_proxy_route_serves_surfaces_below_its_prefix_but_not_at_it() {
        let config = config(|value| add_route(value, "svc", serde_json::json!({ "type": "proxy", "prefix": "/svc" })));

        assert_eq!(config.check_surface_route("/svc/orders"), Ok(()));
        assert!(refusal(&config, "/svc").contains("is not served by any surface prefix"));
    }

    #[test]
    fn a_proxy_route_at_the_root_serves_every_route_no_more_specific_entry_serves() {
        let config = config(|value| {
            value["channels"] = serde_json::json!([]);
            add_route(value, "root", serde_json::json!({ "type": "proxy", "prefix": "" }));
        });

        assert_eq!(config.check_surface_route("/orders"), Ok(()));
        assert_eq!(config.check_surface_route("/agents/foo"), Ok(()));
        assert!(refusal(&config, "/api/foo").contains("is served by route 'api' (identity_api)"));
        assert!(refusal(&config, "/").contains("is not served by any surface prefix"));
    }

    #[test]
    fn the_most_specific_prefix_serves_a_route() {
        let config = config(|value| add_channel(value, "nested", "/api/agents"));

        assert_eq!(config.check_surface_route("/api/agents/foo"), Ok(()));
        assert!(refusal(&config, "/api/other").contains("is served by route 'api' (identity_api)"));
    }

    #[test]
    fn without_surface_prefixes_no_route_is_reachable() {
        let config = config(|value| value["channels"] = serde_json::json!([]));

        assert!(refusal(&config, "/agents/foo").contains("gateway.json declares no surface prefixes"));
    }

    #[test]
    fn a_plain_path_is_a_valid_surface_route() {
        for route in ["/", "/agents/foo", "/agents/a-b_c.d~e", "/agents/v1;x=1", "/agents/f:g@h!&'()*+,"] {
            assert_eq!(check_surface_route_syntax(route), Ok(()), "{route}");
        }
    }

    #[test]
    fn a_route_that_is_not_a_plain_path_is_refused() {
        for route in [
            "agents/foo",
            "/agents/foo$prod",
            "/agents/foo%24prod",
            "/agents//foo",
            "/agents/./foo",
            "/agents/../api",
            "/agents/fo o",
            "/agents/foo\n",
            "/agents/caf\u{e9}",
            "/agents/{id}",
            "/agents/a?b",
            "/agents/a#b",
            "/agents\\a",
        ] {
            let reason = check_surface_route_syntax(route).expect_err(route);
            assert!(reason.contains("must be a plain path"), "{route}: {reason}");
        }
    }

    fn stored_surface(
        id: &str,
        route: &str,
        status: &str,
    ) -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": id, "name": id, "status": status,
            "access_point": {"listen_address": "0.0.0.0:8443", "route": route, "protocol": "a2a"},
            "target": {"endpoint": "http://upstream"}
        }))
        .expect("surface fixture")
    }

    #[test]
    fn only_active_surfaces_callers_cannot_reach_are_unreachable() {
        let surfaces = [
            stored_surface("served", "/agents/foo", "active"),
            stored_surface("outside", "/foo", "active"),
            stored_surface("on-the-api", "/api/foo", "active"),
            stored_surface("disabled", "/bar", "disabled"),
        ];

        let unreachable: Vec<(&str, String)> = config(|_| {})
            .unreachable_surfaces(&surfaces)
            .into_iter()
            .map(|(surface, reason)| (surface.surface_id.as_str(), reason))
            .collect();

        assert_eq!(unreachable.len(), 2, "{unreachable:?}");
        assert_eq!(unreachable[0].0, "outside");
        assert!(
            unreachable[0]
                .1
                .contains("'/foo' is not served by any surface prefix"),
            "{}",
            unreachable[0].1
        );
        assert_eq!(unreachable[1].0, "on-the-api");
        assert!(
            unreachable[1]
                .1
                .contains("is served by route 'api' (identity_api)"),
            "{}",
            unreachable[1].1
        );
    }

    fn load(gateway_json: serde_json::Value) -> anyhow::Result<NetworkConfig> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("gateway.json");
        std::fs::write(&path, gateway_json.to_string()).unwrap();
        NetworkConfig::load_from_file(path.to_str().unwrap())
    }

    fn gateway_json(channel_prefix: &str) -> serde_json::Value {
        serde_json::json!({
            "did": { "domain": "test.local" },
            "webauthn": { "rp_id": "localhost", "external_origin": "https://localhost" },
            "integration": { "types": [], "categories": [] },
            "listeners": [],
            "channels": [{ "id": "files", "name": "Files", "prefix": channel_prefix }],
            "routes": { "avatars": { "type": "static", "prefix": "/avatars", "path": "avatars" } },
        })
    }

    #[test]
    fn loading_a_gateway_json_with_two_entries_on_one_prefix_fails_and_names_both() {
        let error = load(gateway_json("/avatars"))
            .expect_err("two entries on one prefix must not load")
            .to_string();

        assert!(error.contains("'/avatars': channel 'files' and route 'avatars' (static)"), "{error}");
        assert!(error.contains("Give each entry its own prefix"), "{error}");
    }

    #[test]
    fn loading_a_gateway_json_with_distinct_prefixes_succeeds() {
        let config = load(gateway_json("/files")).expect("distinct prefixes load");

        assert_eq!(config.channels[0].prefix, "/files");
    }
}
