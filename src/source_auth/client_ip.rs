//! Resolves the caller's IP address for per-client limits.
//!
//! The address comes from the TCP connection. `X-Forwarded-For` (or RFC 7239 `Forwarded` when
//! `X-Forwarded-For` is absent) is only read when the connecting peer is in
//! `client_auth.trusted_proxies`, and then from the right: trusted proxy hops are skipped and the
//! first untrusted hop is the client. A value a client puts at the left of the header is never
//! reached while a trusted proxy appends the real address after it.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use ipnet::IpNet;

use super::peer_cert::forwarded::ip_in_any;
use crate::config::types::ClientAuthConfig;

/// The caller's IP address, inserted into request extensions by [`resolve_client_ip_layer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

/// Middleware that inserts [`ClientIp`] for every request that carries `ConnectInfo`. Install
/// with `axum::middleware::from_fn_with_state(Arc::new(client_auth_cfg), resolve_client_ip_layer)`
/// on a server built with `into_make_service_with_connect_info`. Without `ConnectInfo` nothing is
/// inserted.
pub async fn resolve_client_ip_layer(
    State(config): State<Arc<ClientAuthConfig>>,
    mut req: Request,
    next: Next,
) -> Response {
    if let Some(peer) = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
    {
        let client_ip = resolve_client_ip(peer, req.headers(), &config.trusted_proxies);
        req.extensions_mut()
            .insert(ClientIp(client_ip));
    }
    next.run(req).await
}

/// The client address for a request that arrived from `peer`. Forwarded headers are ignored
/// unless `peer` is a trusted proxy. Walking from the right, a hop that cannot be parsed stops
/// the walk and the last trusted address wins; when every hop is trusted, the leftmost one wins.
pub fn resolve_client_ip(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpNet],
) -> IpAddr {
    if !ip_in_any(&peer, trusted_proxies) {
        return peer;
    }
    let hops = forwarded_hops(headers);
    let mut resolved = peer;
    for hop in hops.iter().rev() {
        match parse_hop(hop) {
            Some(ip) if ip_in_any(&ip, trusted_proxies) => resolved = ip,
            Some(ip) => return ip,
            None => return resolved,
        }
    }
    resolved
}

/// Every `X-Forwarded-For` entry in order, or every `Forwarded` `for=` value when no
/// `X-Forwarded-For` header is present. Header lines are joined in the order received.
fn forwarded_hops(headers: &HeaderMap) -> Vec<String> {
    let xff: Vec<String> = header_values(headers, "x-forwarded-for")
        .flat_map(|line| {
            line.split(',')
                .map(|hop| hop.trim().to_string())
                .collect::<Vec<_>>()
        })
        .collect();
    if !xff.is_empty() {
        return xff;
    }
    header_values(headers, "forwarded")
        .flat_map(|line| {
            line.split(',')
                .map(|element| {
                    element
                        .split(';')
                        .find_map(|pair| {
                            let (key, value) = pair.split_once('=')?;
                            key.trim()
                                .eq_ignore_ascii_case("for")
                                .then(|| value.trim().to_string())
                        })
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn header_values<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> impl Iterator<Item = &'a str> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
}

/// Accepts `192.0.2.1`, `192.0.2.1:4711`, `2001:db8::1`, `[2001:db8::1]` and
/// `[2001:db8::1]:4711`, with optional quotes as in `Forwarded`. Anything else, such as
/// `unknown` or an obfuscated `_hidden` identifier, is `None`.
fn parse_hop(hop: &str) -> Option<IpAddr> {
    let hop = hop.trim_matches('"');
    if let Ok(ip) = hop.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(addr) = hop.parse::<SocketAddr>() {
        return Some(addr.ip());
    }
    hop.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|inner| inner.parse::<IpAddr>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const PEER: &str = "198.51.100.20";
    const PROXY: &str = "10.0.0.5";
    const INNER_PROXY: &str = "10.0.0.9";
    const CLIENT: &str = "203.0.113.7";
    const SPOOF: &str = "192.0.2.99";

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn trusted() -> Vec<IpNet> {
        vec!["10.0.0.0/8".parse().unwrap()]
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn an_untrusted_peer_is_the_client_whatever_it_forwards() {
        let spoofed = headers(&[("x-forwarded-for", CLIENT), ("forwarded", &format!("for={CLIENT}"))]);

        assert_eq!(resolve_client_ip(ip(PEER), &spoofed, &trusted()), ip(PEER));
        assert_eq!(resolve_client_ip(ip(PROXY), &spoofed, &[]), ip(PROXY));
    }

    #[test]
    fn a_trusted_proxy_forwards_the_client_address() {
        let forwarded = headers(&[("x-forwarded-for", CLIENT)]);

        assert_eq!(resolve_client_ip(ip(PROXY), &forwarded, &trusted()), ip(CLIENT));
    }

    #[test]
    fn trusted_hops_are_skipped_from_the_right() {
        let forwarded = headers(&[("x-forwarded-for", &format!("{CLIENT}, {INNER_PROXY}"))]);

        assert_eq!(resolve_client_ip(ip(PROXY), &forwarded, &trusted()), ip(CLIENT));
    }

    #[test]
    fn a_client_supplied_leftmost_value_is_ignored_behind_a_trusted_proxy() {
        let forwarded = headers(&[("x-forwarded-for", &format!("{SPOOF}, {CLIENT}"))]);

        assert_eq!(resolve_client_ip(ip(PROXY), &forwarded, &trusted()), ip(CLIENT));
    }

    #[test]
    fn header_lines_are_read_in_order() {
        let forwarded =
            headers(&[("x-forwarded-for", SPOOF), ("x-forwarded-for", &format!("{CLIENT}, {INNER_PROXY}"))]);

        assert_eq!(resolve_client_ip(ip(PROXY), &forwarded, &trusted()), ip(CLIENT));
    }

    #[test]
    fn the_rfc_7239_forwarded_header_is_used_without_x_forwarded_for() {
        let forwarded = headers(&[(
            "forwarded",
            &format!("for={SPOOF};proto=https, for=\"[2001:db8::1]:4711\", for={INNER_PROXY}"),
        )]);

        assert_eq!(resolve_client_ip(ip(PROXY), &forwarded, &trusted()), ip("2001:db8::1"));
    }

    #[test]
    fn a_missing_header_resolves_to_the_trusted_proxy() {
        assert_eq!(resolve_client_ip(ip(PROXY), &HeaderMap::new(), &trusted()), ip(PROXY));
    }

    #[test]
    fn an_unparseable_hop_stops_at_the_last_trusted_address() {
        let forwarded = headers(&[("x-forwarded-for", &format!("{CLIENT}, garbage, {INNER_PROXY}"))]);

        assert_eq!(resolve_client_ip(ip(PROXY), &forwarded, &trusted()), ip(INNER_PROXY));
        let only_garbage = headers(&[("forwarded", "for=unknown")]);
        assert_eq!(resolve_client_ip(ip(PROXY), &only_garbage, &trusted()), ip(PROXY));
    }

    #[test]
    fn every_hop_trusted_resolves_to_the_leftmost() {
        let forwarded = headers(&[("x-forwarded-for", &format!("{INNER_PROXY}, 10.1.1.1"))]);

        assert_eq!(resolve_client_ip(ip(PROXY), &forwarded, &trusted()), ip(INNER_PROXY));
    }

    #[test]
    fn hops_with_ports_and_brackets_parse() {
        assert_eq!(parse_hop("192.0.2.1:4711"), Some(ip("192.0.2.1")));
        assert_eq!(parse_hop("[2001:db8::1]"), Some(ip("2001:db8::1")));
        assert_eq!(parse_hop("\"[2001:db8::1]:4711\""), Some(ip("2001:db8::1")));
        assert_eq!(parse_hop("_hidden"), None);
    }

    #[tokio::test]
    async fn the_layer_inserts_the_resolved_client_ip() {
        use axum::{Extension, Router, body::Body, routing::get};
        use tower::ServiceExt;

        let config = Arc::new(ClientAuthConfig {
            trusted_proxies: trusted(),
            ..ClientAuthConfig::default()
        });
        let app = Router::new()
            .route("/", get(|Extension(ClientIp(ip)): Extension<ClientIp>| async move { ip.to_string() }))
            .layer(axum::middleware::from_fn_with_state(config, resolve_client_ip_layer));
        let mut request = Request::builder()
            .uri("/")
            .header("x-forwarded-for", format!("{SPOOF}, {CLIENT}"))
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo::<SocketAddr>(
                format!("{PROXY}:443")
                    .parse()
                    .unwrap(),
            ));

        let response = app
            .oneshot(request)
            .await
            .unwrap();
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();

        assert_eq!(body, CLIENT);
    }
}
