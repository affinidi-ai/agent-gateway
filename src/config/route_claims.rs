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

impl Reach {
    fn includes_prefix(self) -> bool {
        matches!(self, Reach::Prefix | Reach::PrefixAndBelow)
    }

    fn includes_below(self) -> bool {
        matches!(self, Reach::Below | Reach::PrefixAndBelow)
    }
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
    fn overlaps(
        &self,
        other: &RouteClaim,
    ) -> bool {
        self.prefix == other.prefix
            && (self.reach.includes_prefix() && other.reach.includes_prefix()
                || self.reach.includes_below() && other.reach.includes_below())
    }

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

fn hides_dashboard_page(prefix: &str) -> bool {
    crate::proxy::paths::shadowed_dashboard_page(prefix).is_some()
}

impl NetworkConfig {
    /// Read every prefix but a `redirect`'s without a trailing `/`, as surface
    /// routes are matched, so a channel at `/agents/` serves `/agents/foo`. A
    /// root prefix is kept as written; a `redirect` serves its exact path.
    pub(super) fn normalize_route_prefixes(&mut self) {
        fn trim(prefix: &mut String) {
            let trimmed = prefix.trim_end_matches('/');
            if !trimmed.is_empty() && trimmed.len() < prefix.len() {
                *prefix = trimmed.to_string();
            }
        }
        for channel in &mut self.channels {
            trim(&mut channel.prefix);
        }
        for proxy in self
            .mcp_proxies
            .iter_mut()
            .flatten()
        {
            trim(&mut proxy.prefix);
        }
        for route in self
            .routes
            .values_mut()
            .filter(|route| route.route_type != RouteType::Redirect)
        {
            trim(&mut route.prefix);
        }
    }

    /// Every path prefix the inbound router mounts for this configuration, with
    /// its owner. The static fallback serves whatever no other entry does, the
    /// identity API, onboarding, static and connection point routes at `/` serve
    /// only their own paths there, and the router mounts no channel, MCP proxy,
    /// `proxy` or `redirect` prefix that hides a dashboard page, no `redirect`
    /// without a `target` and no `static` route without a `path`, so none of
    /// them claims a prefix.
    fn route_claims(&self) -> Vec<RouteClaim> {
        let channels = self
            .channels
            .iter()
            .filter(|channel| !hides_dashboard_page(&channel.prefix))
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
            .filter(|proxy| !hides_dashboard_page(&proxy.prefix))
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
            .filter(|(_, route)| match route.route_type {
                RouteType::Proxy => !hides_dashboard_page(&route.prefix),
                RouteType::Redirect => route.target.is_some() && !hides_dashboard_page(&route.prefix),
                RouteType::Static => route.path.is_some() && !route.fallback,
                RouteType::IdentityApi | RouteType::Onboarding | RouteType::ConnectionPoint => true,
            })
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

    /// Pairs of entries that mount the same path. The inbound router cannot
    /// serve one path twice: it refuses to start, or one entry hides the other.
    /// A `redirect` serves its prefix only and a `proxy` route or MCP proxy
    /// prefix only the paths below it, so those two share a prefix safely.
    fn route_prefix_clashes(&self) -> Vec<(RouteClaim, RouteClaim)> {
        let claims = self.route_claims();
        claims
            .iter()
            .enumerate()
            .flat_map(|(index, first)| {
                claims[index + 1..]
                    .iter()
                    .filter(|second| first.overlaps(second))
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

    /// Each active surface whose route is not a plain path, once a trailing `/`
    /// is dropped, or that callers cannot reach by its route, with the reason.
    pub fn unservable_surfaces<'a>(
        &self,
        surfaces: &'a [AgentSurface],
    ) -> Vec<(&'a AgentSurface, String)> {
        let claims = self.route_claims();
        surfaces
            .iter()
            .filter(|surface| surface.status != SurfaceStatus::Disabled)
            .filter_map(|surface| {
                let route = &surface.access_point.route;
                check_surface_route_syntax(&normalize_route(route))
                    .and_then(|()| check_route_against(&claims, route))
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
    fn only_active_surfaces_on_routes_callers_cannot_reach_or_that_are_not_plain_paths_are_unservable() {
        let surfaces = [
            stored_surface("served", "/agents/foo", "active"),
            stored_surface("trailing-slash", "/agents/bar/", "active"),
            stored_surface("outside", "/foo", "active"),
            stored_surface("on-the-api", "/api/foo", "active"),
            stored_surface("variant-url", "/agents/foo$prod", "active"),
            stored_surface("disabled", "/bar", "disabled"),
        ];

        let unservable: Vec<(&str, String)> = config(|_| {})
            .unservable_surfaces(&surfaces)
            .into_iter()
            .map(|(surface, reason)| (surface.surface_id.as_str(), reason))
            .collect();

        let expected = [
            ("outside", "'/foo' is not served by any surface prefix"),
            ("on-the-api", "is served by route 'api' (identity_api)"),
            ("variant-url", "must be a plain path"),
        ];
        assert_eq!(unservable.len(), expected.len(), "{unservable:?}");
        for ((id, reason), (expected_id, expected_reason)) in unservable
            .iter()
            .zip(expected)
        {
            assert_eq!(*id, expected_id);
            assert!(reason.contains(expected_reason), "{id}: {reason}");
        }
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

    fn gateway_json_with(
        channels: serde_json::Value,
        routes: serde_json::Value,
    ) -> serde_json::Value {
        let mut value = gateway_json("/files");
        value["channels"] = channels;
        value["routes"] = routes;
        value
    }

    #[test]
    fn a_redirect_shares_a_prefix_with_a_proxy_route_or_an_mcp_proxy_prefix() {
        let loaded = load(gateway_json_with(
            serde_json::json!([]),
            serde_json::json!({
                "docs": { "type": "redirect", "prefix": "/svc", "target": "https://docs.example" },
                "svc": { "type": "proxy", "prefix": "/svc" }
            }),
        ))
        .expect("a redirect beside a proxy route on one prefix loads");
        assert!(
            loaded
                .routes
                .contains_key("svc")
        );

        let clashes = config(|value| {
            add_route(
                value,
                "docs",
                serde_json::json!({ "type": "redirect", "prefix": "/mcp", "target": "https://x" }),
            );
        })
        .route_prefix_clashes();
        assert!(clashes.is_empty(), "{clashes:?}");
    }

    #[test]
    fn entries_that_both_serve_the_prefix_or_both_serve_below_it_clash() {
        for (route, owner) in [
            (
                serde_json::json!({ "type": "redirect", "prefix": "/agents", "target": "https://x" }),
                "route 'first' (redirect)",
            ),
            (serde_json::json!({ "type": "proxy", "prefix": "/agents/" }), "route 'first' (proxy)"),
        ] {
            let clashes = config(|value| add_route(value, "first", route)).route_prefix_clashes();
            assert_eq!(clashes.len(), 1, "{owner}: {clashes:?}");
            assert_eq!((clashes[0].0.owner.as_str(), clashes[0].1.owner.as_str()), ("channel 'agents'", owner));
        }

        let two_proxies = config(|value| {
            add_route(value, "a", serde_json::json!({ "type": "proxy", "prefix": "/svc" }));
            add_route(value, "b", serde_json::json!({ "type": "proxy", "prefix": "/svc" }));
        })
        .route_prefix_clashes();
        assert_eq!(two_proxies.len(), 1, "{two_proxies:?}");
    }

    #[test]
    fn entries_the_router_does_not_mount_claim_nothing() {
        let config = config(|value| {
            add_channel(value, "old-settings", "/settings/old");
            add_route(value, "no-target", serde_json::json!({ "type": "redirect", "prefix": "/agents/docs" }));
            add_route(value, "no-path", serde_json::json!({ "type": "static", "prefix": "/agents/files" }));
            add_route(value, "hidden", serde_json::json!({ "type": "proxy", "prefix": "/policies/svc" }));
        });

        let owners: Vec<String> = config
            .route_claims()
            .into_iter()
            .map(|claim| claim.owner)
            .collect();
        for unmounted in ["channel 'old-settings'", "route 'no-target'", "route 'no-path'", "route 'hidden'"] {
            assert!(
                !owners
                    .iter()
                    .any(|owner| owner.starts_with(unmounted)),
                "{unmounted}: {owners:?}"
            );
        }
        assert!(refusal(&config, "/settings/old/x").contains("is not served by any surface prefix"));
        assert_eq!(config.check_surface_route("/agents/docs"), Ok(()));
        assert_eq!(config.check_surface_route("/agents/files"), Ok(()));
    }

    #[test]
    fn loading_reads_prefixes_without_a_trailing_slash_but_keeps_a_root_and_a_redirect() {
        let config = load(gateway_json_with(
            serde_json::json!([{ "id": "agents", "name": "Agents", "prefix": "/agents/" }]),
            serde_json::json!({
                "root": { "type": "proxy", "prefix": "" },
                "docs": { "type": "redirect", "prefix": "/docs/", "target": "https://docs.example" },
                "files": { "type": "static", "prefix": "/files/", "path": "files" }
            }),
        ))
        .expect("trailing-slash prefixes load");

        assert_eq!(config.channels[0].prefix, "/agents");
        assert_eq!(config.routes["root"].prefix, "");
        assert_eq!(config.routes["docs"].prefix, "/docs/");
        assert_eq!(config.routes["files"].prefix, "/files");
        assert_eq!(config.check_surface_route("/agents/foo"), Ok(()));
    }

    #[test]
    fn loading_two_channels_that_differ_only_by_a_trailing_slash_fails() {
        let error = load(gateway_json_with(
            serde_json::json!([
                { "id": "a", "name": "A", "prefix": "/agents" },
                { "id": "b", "name": "B", "prefix": "/agents/" }
            ]),
            serde_json::json!({}),
        ))
        .expect_err("two channels on one prefix must not load")
        .to_string();

        assert!(error.contains("'/agents': channel 'a' and channel 'b'"), "{error}");
    }

    #[test]
    fn loading_a_gateway_json_with_distinct_prefixes_succeeds() {
        let config = load(gateway_json("/files")).expect("distinct prefixes load");

        assert_eq!(config.channels[0].prefix, "/files");
    }
}
