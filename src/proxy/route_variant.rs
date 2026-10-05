//! Route + variant suffix parsing for surface-snapshot variants.
//!
//! Grammar:
//!
//! ```text
//! INBOUND:   IN_HOST/{route}[$alias][/{rest}]
//! OUTBOUND:  OUT_HOST/{route}[$alias]/{tp-name}[/{rest}]
//! ```
//!
//! The alias is attached to the route with no separator and uses `$` as the
//! sentinel. Percent-encoded `%24` is tolerated equivalently.

/// Result of stripping the route prefix and an optional `$alias` suffix from
/// a request path.
///
/// `alias` is `None` when the request targets the default variant. `tail`
/// always begins with `/` or is empty, ready to be passed to downstream
/// matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMatch<'a> {
    pub alias: Option<&'a str>,
    pub tail: &'a str,
}

/// Parse a request path against a configured surface route.
///
/// Returns `None` when `path` does not start with `route`, when an alias
/// sentinel is present but the alias is empty, or when the character
/// immediately following the route is neither `/`, `$`, end-of-path, nor a
/// `%24` percent-encoded `$`.
///
/// Routes are matched as exact-prefix; callers are expected to normalise
/// trailing slashes before invoking this function.
pub fn parse_route_with_variant<'a>(
    path: &'a str,
    route: &str,
) -> Option<RouteMatch<'a>> {
    let rest = path.strip_prefix(route)?;

    if rest.is_empty() || rest.starts_with('/') {
        return Some(RouteMatch { alias: None, tail: rest });
    }

    // Accept either literal `$` or percent-encoded `%24` as the alias sentinel.
    let after = rest
        .strip_prefix('$')
        .or_else(|| rest.strip_prefix("%24"))
        .or_else(|| rest.strip_prefix("%24"))?;

    let (alias, tail) = match after.find('/') {
        Some(idx) => (&after[..idx], &after[idx..]),
        None => (after, ""),
    };

    if alias.is_empty() {
        return None;
    }

    Some(RouteMatch { alias: Some(alias), tail })
}

/// Convenience wrapper that normalises a configured channel `route` (which
/// may be missing a leading `/`, or be the special `/` catch-all) and then
/// extracts the surface-variant alias from `path`.
///
/// Returns `None` when `path` does not match `route` at all, otherwise
/// `Some(alias_or_none)` where `None` means "default variant".
///
/// This is the single helper the inbound handler, the outbound handler,
/// and the cross-hop ForwardRequest builder all share so the alias-extraction
/// rules stay consistent (plan §2.3 + §4.4).
pub fn extract_variant_alias_for_route(
    path: &str,
    route: &str,
) -> Option<Option<String>> {
    let normalized_route = if route.starts_with('/') {
        route.to_string()
    } else {
        format!("/{}", route)
    };
    // The parser treats "/" specially: an empty prefix matches every path so
    // a leading `$alias` is honoured at the very start.
    let prefix: &str = if normalized_route == "/" {
        ""
    } else {
        normalized_route.as_str()
    };
    parse_route_with_variant(path, prefix).map(|m| m.alias.map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_variant_exact_match() {
        let m = parse_route_with_variant("/api/sales", "/api/sales").unwrap();
        assert_eq!(m.alias, None);
        assert_eq!(m.tail, "");
    }

    #[test]
    fn default_variant_with_tail() {
        let m = parse_route_with_variant("/api/sales/v1/orders", "/api/sales").unwrap();
        assert_eq!(m.alias, None);
        assert_eq!(m.tail, "/v1/orders");
    }

    #[test]
    fn alias_no_tail() {
        let m = parse_route_with_variant("/api/sales$dev", "/api/sales").unwrap();
        assert_eq!(m.alias, Some("dev"));
        assert_eq!(m.tail, "");
    }

    #[test]
    fn alias_with_tail() {
        let m = parse_route_with_variant("/api/sales$dev/v1/orders", "/api/sales").unwrap();
        assert_eq!(m.alias, Some("dev"));
        assert_eq!(m.tail, "/v1/orders");
    }

    #[test]
    fn alias_percent_encoded() {
        let m = parse_route_with_variant("/api/sales%24dev/v1/orders", "/api/sales").unwrap();
        assert_eq!(m.alias, Some("dev"));
        assert_eq!(m.tail, "/v1/orders");
    }

    #[test]
    fn no_match_when_route_not_prefix() {
        assert!(parse_route_with_variant("/other/path", "/api/sales").is_none());
    }

    #[test]
    fn no_match_when_route_partial_segment() {
        // `/api/salesman` should not match route `/api/sales` because the
        // character following the route is neither `/`, `$`, %24, nor end.
        // (It is a literal `m`, which is not a valid sentinel.)
        assert!(parse_route_with_variant("/api/salesman", "/api/sales").is_none());
    }

    #[test]
    fn empty_alias_rejected() {
        assert!(parse_route_with_variant("/api/sales$", "/api/sales").is_none());
        assert!(parse_route_with_variant("/api/sales$/v1", "/api/sales").is_none());
    }

    #[test]
    fn empty_route_inbound_alias() {
        // Edge case from spec §2.3: empty route yields `IN_HOST$alias/...`.
        let m = parse_route_with_variant("$dev/v1/orders", "").unwrap();
        assert_eq!(m.alias, Some("dev"));
        assert_eq!(m.tail, "/v1/orders");
    }

    #[test]
    fn empty_route_default() {
        let m = parse_route_with_variant("/v1/orders", "").unwrap();
        assert_eq!(m.alias, None);
        assert_eq!(m.tail, "/v1/orders");
    }

    #[test]
    fn outbound_alias_with_tp_name() {
        // `/route$dev/tp-name/v1/orders` — caller is responsible for then
        // splitting the TP name out of `tail`.
        let m = parse_route_with_variant("/route$dev/partner-a/v1/orders", "/route").unwrap();
        assert_eq!(m.alias, Some("dev"));
        assert_eq!(m.tail, "/partner-a/v1/orders");
    }

    #[test]
    fn alias_with_hyphen_and_digits() {
        let m = parse_route_with_variant("/r$staging-2/x", "/r").unwrap();
        assert_eq!(m.alias, Some("staging-2"));
        assert_eq!(m.tail, "/x");
    }

    // ── extract_variant_alias_for_route ─────────────────────────────────────
    //
    // These tests pin down the cross-hop carrier (plan §4.4): the value GW1
    // places into `ForwardRequest.body.active_variant_alias` MUST be the
    // alias parsed from the request URL — and `None` for the default
    // variant — regardless of how the channel author wrote the route in
    // config (with/without leading slash, special `/` catch-all).

    #[test]
    fn carrier_default_variant_emits_none() {
        assert_eq!(extract_variant_alias_for_route("/api/sales/v1", "/api/sales"), Some(None));
        assert_eq!(extract_variant_alias_for_route("/api/sales", "/api/sales"), Some(None));
    }

    #[test]
    fn carrier_dollar_alias_emits_alias_string() {
        assert_eq!(extract_variant_alias_for_route("/api/sales$dev/v1", "/api/sales"), Some(Some("dev".to_string())));
    }

    #[test]
    fn carrier_percent_encoded_alias_emits_alias_string() {
        // `%24` MUST be tolerated equivalently to `$` per spec §2.3.
        assert_eq!(extract_variant_alias_for_route("/api/sales%24dev/v1", "/api/sales"), Some(Some("dev".to_string())));
    }

    #[test]
    fn carrier_route_without_leading_slash_normalised() {
        // Channel authors sometimes omit the leading slash; the carrier
        // must normalise so the alias is still extracted.
        assert_eq!(extract_variant_alias_for_route("/api/sales$dev/v1", "api/sales"), Some(Some("dev".to_string())));
    }

    #[test]
    fn carrier_catch_all_route_treats_leading_alias() {
        // Route "/" is the catch-all; alias appears at the very start.
        assert_eq!(extract_variant_alias_for_route("$dev/v1", "/"), Some(Some("dev".to_string())));
        assert_eq!(extract_variant_alias_for_route("/v1", "/"), Some(None));
    }

    #[test]
    fn carrier_path_does_not_match_route_returns_none() {
        // Distinguishes "default variant" (Some(None)) from "route mismatch"
        // (None). The cross-hop builder uses `.and_then(|a| a)` to flatten
        // both into "no alias to forward", which is the correct behaviour
        // when the request didn't actually hit the channel.
        assert_eq!(extract_variant_alias_for_route("/other/path", "/api/sales"), None);
    }

    #[test]
    fn carrier_round_trips_through_forward_request_json() {
        // This is the cross-hop wire-shape contract enforced by plan §4.4:
        // both the legacy `virtual_channel_alias` and the spec-aligned
        // `active_variant_alias` MUST be present and carry the same value.
        // GW2 prefers the new field but falls back to the legacy one.
        let alias = extract_variant_alias_for_route("/api/sales$dev/v1", "/api/sales").and_then(|a| a);
        assert_eq!(alias.as_deref(), Some("dev"));

        let body = serde_json::json!({
            "virtual_channel_alias": alias,
            "active_variant_alias": alias,
        });
        assert_eq!(body["virtual_channel_alias"], "dev");
        assert_eq!(body["active_variant_alias"], "dev");
    }

    #[test]
    fn carrier_default_variant_round_trips_as_null() {
        // The default-variant case MUST produce `null` (not omitted, not
        // empty string) so GW2 can distinguish "default" from "missing".
        let alias = extract_variant_alias_for_route("/api/sales/v1", "/api/sales").and_then(|a| a);
        assert_eq!(alias, None);

        let body = serde_json::json!({
            "virtual_channel_alias": alias,
            "active_variant_alias": alias,
        });
        assert_eq!(body["virtual_channel_alias"], serde_json::Value::Null);
        assert_eq!(body["active_variant_alias"], serde_json::Value::Null);
    }
}
