//! Forwarded-client-cert capture layer.
//!
//! Parses the configured forwarded-cert header (Envoy XFCC by default, or a
//! url-encoded PEM) when the immediate TCP peer is inside the trusted
//! proxies CIDR list, and injects a [`PeerCertInfo`] into the request
//! extensions. Channels that opt-in to `allow_forwarded` (the default) can
//! then authenticate against it.
//!
//! No-op (and zero allocation) when `trusted_proxies` is empty or the peer
//! IP is not trusted — safe to install unconditionally.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use ipnet::IpNet;
use tracing::{debug, warn};

use crate::config::types::{ClientAuthConfig, ForwardedHeaderFormat};
use crate::source_auth::models::{PeerCertInfo, PeerCertSource};

/// Hard cap on the byte length of a forwarded-client-cert header. A
/// PEM-encoded leaf is typically ~2 KiB; 16 KiB leaves comfortable room
/// for chained intermediates while bounding work done on an attacker-
/// supplied header from a (compromised) trusted proxy.
const MAX_FORWARDED_HEADER_BYTES: usize = 16 * 1024;

/// Middleware function: inspect the request, optionally inject
/// [`PeerCertInfo`], then forward to the next layer. Install with
/// `axum::middleware::from_fn_with_state(Arc::new(client_auth_cfg), forwarded_peer_cert)`.
pub async fn forwarded_peer_cert(
    State(config): State<Arc<ClientAuthConfig>>,
    mut req: Request,
    next: Next,
) -> Response {
    if config
        .trusted_proxies
        .is_empty()
    {
        return next.run(req).await;
    }

    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    let Some(peer_ip) = peer_ip else {
        return next.run(req).await;
    };

    if !ip_in_any(&peer_ip, &config.trusted_proxies) {
        return next.run(req).await;
    }

    let Some(raw_header) = req
        .headers()
        .get(
            config
                .forwarded_header
                .header_name
                .as_str(),
        )
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
    else {
        return next.run(req).await;
    };

    if raw_header.len() > MAX_FORWARDED_HEADER_BYTES {
        warn!(
            peer = %peer_ip,
            bytes = raw_header.len(),
            cap = MAX_FORWARDED_HEADER_BYTES,
            "Forwarded-cert header exceeds size cap; ignoring"
        );
        return next.run(req).await;
    }

    match parse_forwarded_header(&raw_header, config.forwarded_header.format) {
        Ok(Some(leaf_der)) => {
            debug!(
                peer = %peer_ip,
                bytes = leaf_der.len(),
                "Captured forwarded peer certificate"
            );
            req.extensions_mut()
                .insert(PeerCertInfo {
                    leaf_der,
                    chain_der: Vec::new(),
                    source: PeerCertSource::Forwarded,
                });
        }
        Ok(None) => {
            debug!(peer = %peer_ip, "Forwarded-cert header present but contained no Cert= element");
        }
        Err(e) => {
            warn!(peer = %peer_ip, error = %e, "Failed to parse forwarded-cert header");
        }
    }

    req.headers_mut().remove(
        config
            .forwarded_header
            .header_name
            .as_str(),
    );

    next.run(req).await
}

fn ip_in_any(
    ip: &IpAddr,
    cidrs: &[IpNet],
) -> bool {
    cidrs
        .iter()
        .any(|c| c.contains(ip))
}

/// Parse a forwarded-client-cert header value into the leaf certificate's
/// DER bytes. Returns `Ok(None)` when the header is well-formed but does
/// not carry a leaf certificate (e.g. an Envoy XFCC entry with only
/// `Hash=`/`Subject=` and no `Cert=`).
pub fn parse_forwarded_header(
    raw: &str,
    format: ForwardedHeaderFormat,
) -> Result<Option<Vec<u8>>, String> {
    let pem_string = match format {
        ForwardedHeaderFormat::EnvoyXfcc => extract_xfcc_cert(raw)?,
        ForwardedHeaderFormat::UrlEncodedPem => Some(url_decode(raw)?),
    };

    let Some(pem) = pem_string else {
        return Ok(None);
    };

    let der = decode_pem_certificate(pem.as_bytes())?;
    Ok(Some(der))
}

/// Envoy's XFCC grammar is a comma-separated list of semicolon-separated
/// `Key=Value` pairs. The `Cert` value is a URL-encoded, double-quoted
/// PEM string. We only consume the first element (the immediate client)
/// and ignore subsequent forwarding hops, matching the recommendation in
/// the Envoy docs.
fn extract_xfcc_cert(raw: &str) -> Result<Option<String>, String> {
    let first = raw
        .split(',')
        .next()
        .unwrap_or("")
        .trim();
    if first.is_empty() {
        return Ok(None);
    }

    for pair in split_xfcc_pairs(first) {
        let trimmed = pair.trim();
        let Some((key, value)) = split_key_value(trimmed) else {
            continue;
        };
        if key.eq_ignore_ascii_case("Cert") {
            let unquoted = strip_quotes(value);
            let decoded = url_decode(unquoted)?;
            if decoded.contains("-----BEGIN CERTIFICATE-----") {
                return Ok(Some(decoded));
            }
            return Err("Cert= value did not contain a PEM CERTIFICATE block".to_string());
        }
    }
    Ok(None)
}

/// Split an XFCC entry on `;` while respecting `"..."` quoting (the
/// quoted `Cert=` value contains URL-encoded `;` which must NOT be
/// treated as a pair separator).
fn split_xfcc_pairs(entry: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_quotes = false;
    let mut start = 0usize;
    let bytes = entry.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        match *b {
            b'"' => in_quotes = !in_quotes,
            b';' if !in_quotes => {
                out.push(&entry[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < entry.len() {
        out.push(&entry[start..]);
    }
    out
}

fn split_key_value(pair: &str) -> Option<(&str, &str)> {
    let eq = pair.find('=')?;
    Some((&pair[..eq], &pair[eq + 1..]))
}

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Minimal `application/x-www-form-urlencoded`-style decoder: handles
/// `%XX` escapes. Plus (`+`) is left as-is because PEM never contains it
/// in a context where it would mean space. Returns an error if the
/// decoded bytes are not valid UTF-8 (PEM is strict ASCII so any
/// non-UTF-8 byte indicates a malformed or hostile header).
fn url_decode(input: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).map_err(|e| format!("URL-decoded bytes are not valid UTF-8: {e}"))
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_pem_certificate(pem_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem_bytes).map_err(|e| format!("PEM parse error: {e}"))?;
    if parsed.label != "CERTIFICATE" {
        return Err(format!("Expected PEM tag 'CERTIFICATE', got '{}'", parsed.label));
    }
    Ok(parsed.contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::ForwardedHeaderConfig;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::StatusCode;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use tower::ServiceExt;

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn sample_pem() -> String {
        use rcgen::{CertificateParams, KeyPair};
        let kp = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["example.com".to_string()])
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        cert.pem()
    }

    fn url_encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len() * 3);
        for b in s.bytes() {
            match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    async fn introspect(req: Request) -> String {
        match req
            .extensions()
            .get::<PeerCertInfo>()
        {
            Some(p) => format!("yes:{:?}:{}", p.source, p.leaf_der.len()),
            None => "no".to_string(),
        }
    }

    async fn run_through_layer(
        cfg: ClientAuthConfig,
        peer: &str,
        header: Option<(&str, String)>,
    ) -> String {
        let app: Router = Router::new()
            .route("/", get(introspect))
            .layer(from_fn_with_state(Arc::new(cfg), forwarded_peer_cert));

        let mut builder = Request::builder().uri("/");
        if let Some((name, val)) = header {
            builder = builder.header(name, val);
        }
        let mut req = builder
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo::<SocketAddr>(peer.parse().unwrap()));

        let resp = app
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    // ── parse_forwarded_header ─────────────────────────────────────────────

    #[test]
    fn xfcc_extracts_cert_from_first_entry() {
        let pem = sample_pem();
        let enc = url_encode(&pem);
        let header = format!("By=spiffe://x/y;Hash=abc;Cert=\"{enc}\";Subject=\"CN=client\"");
        let der = parse_forwarded_header(&header, ForwardedHeaderFormat::EnvoyXfcc)
            .unwrap()
            .expect("expected leaf der");
        assert!(!der.is_empty());
    }

    #[test]
    fn xfcc_ignores_subsequent_hops() {
        let pem = sample_pem();
        let enc = url_encode(&pem);
        let header = format!("Cert=\"{enc}\",Subject=\"CN=ignored\"");
        parse_forwarded_header(&header, ForwardedHeaderFormat::EnvoyXfcc)
            .unwrap()
            .expect("first hop cert");
    }

    #[test]
    fn xfcc_returns_none_when_no_cert_element() {
        let header = "By=spiffe://x/y;Hash=abc;Subject=\"CN=client\"";
        let result = parse_forwarded_header(header, ForwardedHeaderFormat::EnvoyXfcc).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn xfcc_handles_semicolons_inside_quoted_cert() {
        let pem = sample_pem();
        let enc = url_encode(&pem);
        let header = format!("Cert=\"{enc}\";Subject=\"CN=a;OU=b;O=c\"");
        parse_forwarded_header(&header, ForwardedHeaderFormat::EnvoyXfcc)
            .unwrap()
            .expect("cert should still extract");
    }

    #[test]
    fn url_encoded_pem_format_works() {
        let pem = sample_pem();
        let enc = url_encode(&pem);
        let der = parse_forwarded_header(&enc, ForwardedHeaderFormat::UrlEncodedPem)
            .unwrap()
            .expect("expected der");
        assert!(!der.is_empty());
    }

    #[test]
    fn xfcc_cert_value_without_pem_block_is_error() {
        let header = "Cert=\"not-a-pem\";Subject=\"CN=x\"";
        let err = parse_forwarded_header(header, ForwardedHeaderFormat::EnvoyXfcc).unwrap_err();
        assert!(err.contains("CERTIFICATE"));
    }

    // ── ip_in_any ──────────────────────────────────────────────────────────

    #[test]
    fn ip_in_any_v4_cidr() {
        let cidrs: Vec<IpNet> = vec![
            "10.0.0.0/8".parse().unwrap(),
            "192.168.1.0/24"
                .parse()
                .unwrap(),
        ];
        assert!(ip_in_any(&"10.5.6.7".parse().unwrap(), &cidrs));
        assert!(ip_in_any(
            &"192.168.1.100"
                .parse()
                .unwrap(),
            &cidrs
        ));
        assert!(!ip_in_any(&"8.8.8.8".parse().unwrap(), &cidrs));
    }

    #[test]
    fn ip_in_any_v6_cidr() {
        let cidrs: Vec<IpNet> = vec!["fd00::/8".parse().unwrap()];
        assert!(ip_in_any(&"fd12::1".parse().unwrap(), &cidrs));
        assert!(!ip_in_any(&"2001:db8::1".parse().unwrap(), &cidrs));
    }

    // ── Layer behaviour (through real Router) ──────────────────────────────

    #[tokio::test]
    async fn layer_noop_when_trusted_proxies_empty() {
        let result = run_through_layer(
            ClientAuthConfig::default(),
            "127.0.0.1:1234",
            Some(("x-forwarded-client-cert", "Cert=\"garbage\"".to_string())),
        )
        .await;
        assert_eq!(result, "no");
    }

    #[tokio::test]
    async fn layer_injects_peer_cert_when_proxy_trusted() {
        let cfg = ClientAuthConfig {
            direct: Default::default(),
            trusted_proxies: vec!["127.0.0.0/8".parse().unwrap()],
            forwarded_header: ForwardedHeaderConfig::default(),
        };
        let pem = sample_pem();
        let enc = url_encode(&pem);
        let header_value = format!("Cert=\"{enc}\";Subject=\"CN=client\"");
        let result = run_through_layer(cfg, "127.0.0.1:1234", Some(("x-forwarded-client-cert", header_value))).await;
        assert!(result.starts_with("yes:Forwarded:"), "expected injection, got: {result}");
    }

    #[tokio::test]
    async fn layer_skips_untrusted_proxy() {
        let cfg = ClientAuthConfig {
            direct: Default::default(),
            trusted_proxies: vec!["10.0.0.0/8".parse().unwrap()],
            forwarded_header: ForwardedHeaderConfig::default(),
        };
        let pem = sample_pem();
        let enc = url_encode(&pem);
        let header_value = format!("Cert=\"{enc}\"");
        let result = run_through_layer(cfg, "8.8.8.8:1234", Some(("x-forwarded-client-cert", header_value))).await;
        assert_eq!(result, "no");
    }

    #[tokio::test]
    async fn layer_skips_when_header_absent() {
        let cfg = ClientAuthConfig {
            direct: Default::default(),
            trusted_proxies: vec!["127.0.0.0/8".parse().unwrap()],
            forwarded_header: ForwardedHeaderConfig::default(),
        };
        let result = run_through_layer(cfg, "127.0.0.1:1234", None).await;
        assert_eq!(result, "no");
    }
}
