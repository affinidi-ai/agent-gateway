//! Shared SSRF-safe egress guard primitive.
//!
//! One place to validate an outbound URL, pin it to the exact IP address(es)
//! it resolved to, and send through a redirect-disabled client that re-vets
//! every hop. This closes the two-part SSRF gap the individual sinks have:
//! (1) a hostname that passes a static check can still resolve to an internal
//! address (DNS rebinding), and (2) a redirect can send a validated request to
//! an internal address afterwards.
//!
//! Two policies express the trust levels in the codebase:
//! - [`EgressPolicy::Strict`] for attacker-influenceable URLs — blocks cloud
//!   metadata, loopback, RFC 1918, link-local and ULA (the
//!   `validate_webhook_url` family).
//! - [`EgressPolicy::Configured`] for a stored backend vetted at save time with
//!   `validate_resolved_url` — blocks cloud metadata, loopback and unspecified
//!   addresses, and allows RFC 1918 so a same-VPC backend still works.
//!
//! The attacker-influenceable sinks (mediator and trust-registry DID fetches,
//! A2A-proxy dials) call [`guarded_send_inner`] directly, each threading its
//! own exact allow-list.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, COOKIE, HeaderMap, LOCATION, PROXY_AUTHORIZATION};
use reqwest::{Client, Method, Response};
use url::Url;

use crate::url_validation::{
    is_blocked_resolved_ip, is_blocked_resolved_webhook_ip, is_cloud_metadata_resolved_ip,
    validate_resolved_cloud_metadata_url, validate_resolved_url, validate_url_not_cloud_metadata, validate_webhook_url,
};

/// Maximum number of redirects [`guarded_send_inner`] will follow before giving up.
const MAX_REDIRECTS: usize = 5;

/// Trust level applied when validating and pinning an egress target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressPolicy {
    /// Attacker-influenceable URLs (webhooks, payment proxies, user-supplied
    /// endpoints). Blocks cloud metadata, loopback, RFC 1918, link-local and
    /// IPv6 ULA — statically and after DNS resolution.
    Strict,
    /// A stored backend whose URL was vetted with `validate_resolved_url` when
    /// it was saved. Applies that same policy at call time, so a host that
    /// rebinds to loopback after the save is refused.
    Configured,
}

impl EgressPolicy {
    /// Static (pre-DNS) validation for this policy: scheme, credentials, host
    /// syntax and IP-literal ranges. Returns the parsed URL.
    fn static_validate(
        self,
        raw: &str,
    ) -> Result<Url, String> {
        match self {
            EgressPolicy::Strict => validate_webhook_url(raw),
            EgressPolicy::Configured => validate_url_not_cloud_metadata(raw),
        }
    }

    /// Per-resolved-IP block predicate for this policy.
    fn is_blocked_ip(
        self,
        ip: IpAddr,
    ) -> bool {
        match self {
            EgressPolicy::Strict => is_blocked_resolved_webhook_ip(ip),
            EgressPolicy::Configured => is_blocked_resolved_ip(ip),
        }
    }
}

/// A validated egress target pinned to the exact addresses it resolved to.
///
/// `addrs` are the vetted socket addresses; a pinned client connects only to
/// these, so DNS cannot be re-resolved to a different (internal) address
/// between validation and connection. Pinning is HTTPS-safe: SNI and
/// certificate verification stay bound to `host`.
#[derive(Debug, Clone)]
pub struct PinnedTarget {
    pub url: Url,
    pub host: String,
    pub addrs: Vec<SocketAddr>,
}

/// Errors from the egress guard. Every failure path is fail-closed: a parse
/// failure, DNS failure, or blocked address returns `Err`, never a usable
/// target.
#[derive(Debug)]
pub enum EgressError {
    /// The target (or a resolved/redirect address) is blocked by policy.
    Blocked(String),
    /// DNS resolution failed or returned no addresses.
    Dns(String),
    /// The redirect chain exceeded [`MAX_REDIRECTS`].
    TooManyRedirects,
    /// The underlying HTTP request failed.
    Http(reqwest::Error),
    /// The URL (or a redirect `Location`) could not be parsed.
    Parse(String),
}

impl std::fmt::Display for EgressError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            EgressError::Blocked(m) => write!(f, "egress target blocked: {m}"),
            EgressError::Dns(m) => write!(f, "egress DNS resolution failed: {m}"),
            EgressError::TooManyRedirects => {
                write!(f, "egress redirect chain exceeded {MAX_REDIRECTS} hops")
            }
            EgressError::Http(e) => write!(f, "egress request failed: {e}"),
            EgressError::Parse(m) => write!(f, "egress URL parse failed: {m}"),
        }
    }
}

impl std::error::Error for EgressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EgressError::Http(e) => Some(e),
            _ => None,
        }
    }
}

/// Reads the BDD egress allow-list, gated on `AG_TEST_MODE=true`.
///
/// Entries are matched exact-URL, or by origin when an entry carries no path
/// (see [`allowlist_entry_matches`]).
///
/// Mirrors `url_validation::bdd_oauth_endpoint_allowlist`: both env vars must be
/// set, so a bare `AG_TEST_MODE` never relaxes egress. Returns `None` on the
/// production path (env unset), leaving validation strict.
pub(crate) fn bdd_egress_allowlist() -> Option<String> {
    if std::env::var("AG_TEST_MODE").as_deref() != Ok("true") {
        return None;
    }
    std::env::var("AG_BDD_EGRESS_ALLOWLIST")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// Parses the comma-separated allow-list, validating each entry through the
/// metadata-blocking validator so a metadata endpoint can never be allow-listed.
fn parse_egress_allowlist(raw: &str) -> Result<Vec<Url>, EgressError> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| validate_resolved_cloud_metadata_url(entry).map_err(EgressError::Blocked))
        .collect()
}

/// Matches a BDD allow-list entry against a candidate egress URL.
///
/// A path-bearing entry must match the candidate exactly (unchanged strict
/// behaviour). An *origin-only* entry — no path, query, or fragment — matches
/// any URL sharing its scheme+host+port, so a dynamic path/query (for example
/// an OOB invitation `…/oob?_oobid=<random>`) is permitted without pinning the
/// exact URL. Metadata endpoints are already rejected by
/// [`parse_egress_allowlist`], so origin matching can never widen to metadata.
fn allowlist_entry_matches(
    entry: &Url,
    candidate: &Url,
) -> bool {
    if entry == candidate {
        return true;
    }
    let entry_is_origin_only = entry
        .path()
        .trim_end_matches('/')
        .is_empty()
        && entry.query().is_none()
        && entry.fragment().is_none();
    entry_is_origin_only && entry.origin() == candidate.origin()
}

/// Resolves `host:port` to socket addresses (blocking OS resolver), failing
/// closed on error or an empty result.
fn resolve_addrs(
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, EgressError> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| EgressError::Dns(format!("{host}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(EgressError::Dns(format!("{host}: no addresses")));
    }
    Ok(addrs)
}

/// Resolves `url`, vets every resolved address with `blocked`, and returns the
/// pinned target.
fn pin_url(
    url: Url,
    blocked: impl Fn(IpAddr) -> bool,
) -> Result<PinnedTarget, EgressError> {
    let host = url
        .host_str()
        .ok_or_else(|| EgressError::Parse("URL must include a host".into()))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| EgressError::Parse("URL must include a port".into()))?;

    let addrs = resolve_addrs(&host, port)?;
    for addr in &addrs {
        if blocked(addr.ip()) {
            return Err(EgressError::Blocked(format!("host '{host}' resolves to blocked address '{}'", addr.ip())));
        }
    }
    Ok(PinnedTarget { url, host, addrs })
}

fn validate_and_pin_inner(
    raw: &str,
    policy: EgressPolicy,
    exact_allowlist: Option<&str>,
) -> Result<PinnedTarget, EgressError> {
    match policy.static_validate(raw) {
        Ok(url) => pin_url(url, |ip| policy.is_blocked_ip(ip)),
        Err(production_error) => {
            let Some(allowlist_raw) = exact_allowlist else {
                return Err(EgressError::Blocked(production_error));
            };
            // Never relax metadata, even for an allow-listed entry.
            let candidate = validate_resolved_cloud_metadata_url(raw).map_err(EgressError::Blocked)?;
            let allowed = parse_egress_allowlist(allowlist_raw)?;
            if allowed
                .iter()
                .any(|entry| allowlist_entry_matches(entry, &candidate))
            {
                pin_url(candidate, is_cloud_metadata_resolved_ip)
            } else {
                Err(EgressError::Blocked(format!(
                    "{production_error}; egress URL '{candidate}' is not in the exact allow-list"
                )))
            }
        }
    }
}

/// Builds a redirect-disabled client pinned to `target`'s vetted addresses.
///
/// `resolve_to_addrs` is builder-only in reqwest 0.13, so a fresh client is
/// built per pinned target — acceptable for guarded egress.
fn pinned_client(
    target: &PinnedTarget,
    timeout: Duration,
) -> Result<Client, EgressError> {
    Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(&target.host, &target.addrs)
        .build()
        .map_err(EgressError::Http)
}

/// Resolve + pin `vetted_url` with `blocked` and return a redirect-disabled
/// client pinned to the exact address it resolved to.
///
/// Shared body of [`pinned_forward_client`] and [`pinned_strict_client`]; the
/// caller supplies the already-vetted URL and the per-resolved-IP block
/// predicate matching the policy it validated with.
fn pin_and_build(
    vetted_url: Url,
    blocked: impl Fn(IpAddr) -> bool,
    timeout: Duration,
) -> Result<(Client, PinnedTarget), EgressError> {
    let target = pin_url(vetted_url, blocked)?;
    let client = pinned_client(&target, timeout)?;
    Ok((client, target))
}

/// Vet a proxy-forward target with the cloud-metadata-only policy and return a
/// redirect-disabled client pinned to the exact address it resolved to.
///
/// Same policy as the forwarding-layer static check
/// ([`validate_resolved_cloud_metadata_url`]): blocks only cloud metadata,
/// allows loopback and RFC 1918 so an operator-configured surface can forward to
/// a localhost sidecar or same-VPC upstream. Pins the connection to the vetted
/// address so DNS cannot be re-resolved to an internal address between vetting
/// and connect (rebinding TOCTOU), and disables redirects so an upstream 3xx is
/// returned to the caller rather than followed to an unvetted `Location`.
///
/// Resolves DNS (blocking OS resolver); call from a blocking context.
pub(crate) fn pinned_forward_client(
    raw_url: &str,
    timeout: Duration,
) -> Result<(Client, PinnedTarget), EgressError> {
    let url = validate_resolved_cloud_metadata_url(raw_url).map_err(EgressError::Blocked)?;
    pin_and_build(url, is_cloud_metadata_resolved_ip, timeout)
}

/// Vet an attacker-influenceable target with the Strict policy and return a
/// redirect-disabled client pinned to the exact address it resolved to.
///
/// Strict sibling of [`pinned_forward_client`]: vets with
/// [`validate_resolved_url`] (blocks cloud metadata and loopback) and pins with
/// the [`EgressPolicy::Strict`] per-resolved-IP predicate (also RFC 1918), so a
/// caller-supplied endpoint (e.g. MCP tool discovery) cannot re-resolve to an
/// internal address between vetting and connect (rebinding TOCTOU). Redirects
/// are disabled so an upstream 3xx is returned rather than followed.
///
/// Resolves DNS (blocking OS resolver); call from a blocking context.
pub(crate) fn pinned_strict_client(
    raw_url: &str,
    timeout: Duration,
) -> Result<(Client, PinnedTarget), EgressError> {
    let url = validate_resolved_url(raw_url).map_err(EgressError::Blocked)?;
    pin_and_build(url, |ip| EgressPolicy::Strict.is_blocked_ip(ip), timeout)
}

/// Vet a stored backend with [`EgressPolicy::Configured`] and return a
/// redirect-disabled client pinned to the exact address it resolved to.
///
/// `exact_allowlist` is the BDD allow-list ([`bdd_egress_allowlist`] on the
/// production path), which can admit an exact loopback fixture but never cloud
/// metadata.
///
/// Resolves DNS (blocking OS resolver); call from a blocking context.
pub(crate) fn pinned_configured_client(
    raw_url: &str,
    timeout: Duration,
    exact_allowlist: Option<&str>,
) -> Result<(Client, PinnedTarget), EgressError> {
    let target = validate_and_pin_inner(raw_url, EgressPolicy::Configured, exact_allowlist)?;
    let client = pinned_client(&target, timeout)?;
    Ok((client, target))
}

/// Send `method raw_url` through the guard: validate + pin the initial URL,
/// send with a redirect-disabled pinned client, then follow up to
/// [`MAX_REDIRECTS`] 3xx hops manually — re-validating and re-pinning every
/// hop.
///
/// A **cross-origin** redirect strips credential headers (`Authorization`,
/// `Cookie`, `Proxy-Authorization`) and drops the request body before
/// re-sending, matching reqwest's built-in redirect safety that `Policy::none()`
/// otherwise bypasses. Same-origin hops replay headers and body verbatim.
///
/// `exact_allowlist` is the caller's own BDD test allow-list (exact-URL, or
/// origin-only entries per [`allowlist_entry_matches`]); production sinks
/// resolve it from [`bdd_egress_allowlist`], `None` on the production path.
pub(crate) async fn guarded_send_inner(
    method: Method,
    raw_url: &str,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
    policy: EgressPolicy,
    timeout: Duration,
    exact_allowlist: Option<&str>,
) -> Result<Response, EgressError> {
    let mut current = raw_url.to_string();
    let mut headers = headers;
    let mut body = body;

    for _ in 0..=MAX_REDIRECTS {
        let target = resolve_pin_blocking(current.clone(), policy, exact_allowlist).await?;
        let client = pinned_client(&target, timeout)?;

        let mut req = client
            .request(method.clone(), target.url.clone())
            .headers(headers.clone());
        if let Some(bytes) = &body {
            req = req.body(bytes.clone());
        }

        let resp = req
            .send()
            .await
            .map_err(EgressError::Http)?;

        if resp.status().is_redirection()
            && let Some(location) = resp.headers().get(LOCATION)
        {
            let location = location
                .to_str()
                .map_err(|e| EgressError::Parse(format!("invalid Location header: {e}")))?;
            let next = target
                .url
                .join(location)
                .map_err(|e| EgressError::Parse(format!("invalid redirect target: {e}")))?;

            if next.origin() != target.url.origin() {
                headers.remove(AUTHORIZATION);
                headers.remove(COOKIE);
                headers.remove(PROXY_AUTHORIZATION);
                body = None;
            }

            current = next.into();
            continue;
        }

        return Ok(resp);
    }

    Err(EgressError::TooManyRedirects)
}

/// Runs the blocking validate + DNS resolve off the async runtime.
///
/// `validate_and_pin_inner` resolves DNS with the blocking OS resolver; on the
/// shared async egress path this is moved to a blocking pool so it cannot stall
/// runtime worker threads.
async fn resolve_pin_blocking(
    raw: String,
    policy: EgressPolicy,
    exact_allowlist: Option<&str>,
) -> Result<PinnedTarget, EgressError> {
    let allowlist = exact_allowlist.map(str::to_string);
    tokio::task::spawn_blocking(move || validate_and_pin_inner(&raw, policy, allowlist.as_deref()))
        .await
        .map_err(|e| EgressError::Dns(format!("resolver task failed: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn pin_strict(raw: &str) -> Result<PinnedTarget, EgressError> {
        validate_and_pin_inner(raw, EgressPolicy::Strict, None)
    }

    #[test]
    fn pins_public_ip_literal_to_vetted_addr() {
        let pinned = pin_strict("https://1.2.3.4/api").expect("public IP must pin");
        assert_eq!(pinned.host, "1.2.3.4");
        assert_eq!(pinned.addrs, vec!["1.2.3.4:443".parse().unwrap()]);
    }

    #[test]
    fn strict_blocks_rfc1918_loopback_link_local_and_metadata() {
        for raw in [
            "http://10.0.0.1/hook",
            "http://192.168.1.1/hook",
            "http://172.16.0.1/hook",
            "http://127.0.0.1/hook",
            "http://169.254.1.1/hook",
            "http://169.254.169.254/latest/meta-data/",
        ] {
            assert!(matches!(pin_strict(raw), Err(EgressError::Blocked(_))), "strict must block {raw}");
        }
    }

    #[test]
    fn strict_blocks_obfuscated_and_mapped_internal_forms() {
        // Numeric/obfuscated IPv4 forms the `url` crate normalizes, plus
        // IPv4-mapped IPv6 forms of internal addresses. Every one must be blocked
        // statically before any DNS/connection under the Strict policy the SSRF
        // sinks (OOB + a2a dial) use.
        for raw in [
            "http://2130706433/",        // decimal 127.0.0.1
            "http://0x7f000001/",        // hex 127.0.0.1
            "http://0x7f.0.0.1/",        // mixed-hex-octet 127.0.0.1
            "http://2852039166/latest/", // decimal 169.254.169.254
            "http://0xa9fea9fe/latest/", // hex 169.254.169.254
            "http://[::ffff:169.254.169.254]/",
            "http://[::ffff:10.0.0.1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://127.0.0.1@evil.com/", // credential-form: host is evil.com but creds are rejected
        ] {
            assert!(
                matches!(pin_strict(raw), Err(EgressError::Blocked(_))),
                "strict must block obfuscated internal form {raw}, got {:?}",
                pin_strict(raw)
            );
        }
    }

    #[test]
    fn configured_blocks_loopback_and_metadata_but_allows_private_ranges() {
        for raw in [
            "http://127.0.0.1/api",
            "http://[::1]/api",
            "http://0.0.0.0/api",
            "http://[::ffff:127.0.0.1]/api",
            "http://169.254.169.254/latest/meta-data/",
        ] {
            assert!(
                matches!(validate_and_pin_inner(raw, EgressPolicy::Configured, None), Err(EgressError::Blocked(_))),
                "configured must block {raw}"
            );
        }
        for raw in ["http://10.0.0.1/api", "http://192.168.1.1/api", "https://1.2.3.4/api"] {
            assert!(validate_and_pin_inner(raw, EgressPolicy::Configured, None).is_ok(), "configured must allow {raw}");
        }
        assert!(
            pinned_configured_client("http://127.0.0.1:9/api", Duration::from_secs(1), Some("http://127.0.0.1:9"))
                .is_ok(),
            "an allow-listed loopback fixture is reachable"
        );
        assert!(
            pinned_configured_client(
                "http://169.254.169.254/latest/",
                Duration::from_secs(1),
                Some("http://169.254.169.254")
            )
            .is_err(),
            "metadata is never allow-listed"
        );
    }

    #[test]
    fn parse_error_fails_closed() {
        assert!(matches!(pin_strict("not a url"), Err(EgressError::Blocked(_))));
        assert!(matches!(pin_strict("ftp://example.com/"), Err(EgressError::Blocked(_))));
    }

    #[test]
    fn dns_failure_fails_closed() {
        // `.invalid` is reserved (RFC 2606) and never resolves.
        let result = pin_strict("http://nonexistent.host.invalid/hook");
        assert!(matches!(result, Err(EgressError::Dns(_))), "got {result:?}");
    }

    #[test]
    fn allowlist_permits_exact_loopback_only_and_never_metadata() {
        let allow = "http://127.0.0.1:9/ok";

        let ok = validate_and_pin_inner("http://127.0.0.1:9/ok", EgressPolicy::Strict, Some(allow))
            .expect("exact allow-listed loopback must pass");
        assert_eq!(ok.addrs, vec!["127.0.0.1:9".parse().unwrap()]);

        assert!(
            matches!(
                validate_and_pin_inner("http://127.0.0.1:10/ok", EgressPolicy::Strict, Some(allow)),
                Err(EgressError::Blocked(_))
            ),
            "non-listed loopback must still fail"
        );

        assert!(
            matches!(
                validate_and_pin_inner(
                    "http://169.254.169.254/latest/meta-data/",
                    EgressPolicy::Strict,
                    Some("http://169.254.169.254/latest/meta-data/"),
                ),
                Err(EgressError::Blocked(_))
            ),
            "metadata must never be allow-listed"
        );
    }

    #[test]
    fn origin_only_allowlist_entry_matches_any_path_on_that_origin() {
        // An origin-only entry (no path) allows a dynamic path/query on the same
        // scheme+host+port — e.g. an OOB invitation `…/oob?_oobid=<random>`.
        let allow = "http://127.0.0.1:9";

        let ok = validate_and_pin_inner("http://127.0.0.1:9/oob?_oobid=abc123", EgressPolicy::Strict, Some(allow))
            .expect("origin-only allow-listed loopback must pass any path");
        assert_eq!(ok.addrs, vec!["127.0.0.1:9".parse().unwrap()]);

        // A different port on the same host is still blocked.
        assert!(
            matches!(
                validate_and_pin_inner("http://127.0.0.1:10/oob?_oobid=abc123", EgressPolicy::Strict, Some(allow)),
                Err(EgressError::Blocked(_))
            ),
            "an origin-only entry must not widen to other ports"
        );

        // A path-bearing entry still requires an exact match (unchanged).
        let path_allow = "http://127.0.0.1:9/ok";
        assert!(
            matches!(
                validate_and_pin_inner("http://127.0.0.1:9/other", EgressPolicy::Strict, Some(path_allow)),
                Err(EgressError::Blocked(_))
            ),
            "a path-bearing entry must not match a different path"
        );

        // Origin matching never widens to metadata.
        assert!(
            matches!(
                validate_and_pin_inner(
                    "http://169.254.169.254/latest/meta-data/",
                    EgressPolicy::Strict,
                    Some("http://169.254.169.254")
                ),
                Err(EgressError::Blocked(_))
            ),
            "an origin-only metadata entry must still be rejected"
        );
    }

    /// Spawns a loopback HTTP server that answers every request with `response`.
    async fn spawn_server(response: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(response.as_bytes())
                    .await;
                let _ = sock.flush().await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn guarded_send_rejects_redirect_to_blocked_host() {
        let addr =
            spawn_server("HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\n\r\n").await;
        let start = format!("http://{addr}/start");

        let result = guarded_send_inner(
            Method::GET,
            &start,
            HeaderMap::new(),
            None,
            EgressPolicy::Strict,
            Duration::from_secs(5),
            Some(&start),
        )
        .await;

        assert!(matches!(result, Err(EgressError::Blocked(_))), "redirect to metadata must be blocked, got {result:?}");
    }

    #[tokio::test]
    async fn guarded_send_enforces_hop_cap() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let loop_url = format!("http://{addr}/loop");
        let response = format!("HTTP/1.1 302 Found\r\nLocation: {loop_url}\r\nContent-Length: 0\r\n\r\n");
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(response.as_bytes())
                    .await;
                let _ = sock.flush().await;
            }
        });

        let result = guarded_send_inner(
            Method::GET,
            &loop_url,
            HeaderMap::new(),
            None,
            EgressPolicy::Strict,
            Duration::from_secs(5),
            Some(&loop_url),
        )
        .await;

        assert!(
            matches!(result, Err(EgressError::TooManyRedirects)),
            "self-redirect loop must hit the hop cap, got {result:?}"
        );
    }

    #[tokio::test]
    async fn guarded_send_returns_non_redirect_response() {
        let addr = spawn_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let url = format!("http://{addr}/ok");

        let resp = guarded_send_inner(
            Method::GET,
            &url,
            HeaderMap::new(),
            None,
            EgressPolicy::Strict,
            Duration::from_secs(5),
            Some(&url),
        )
        .await
        .expect("allow-listed loopback GET must succeed");

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "ok");
    }

    #[tokio::test]
    async fn guarded_send_strips_credentials_and_body_on_cross_origin_redirect() {
        use tokio::sync::oneshot;

        // Sink server on a distinct loopback port (a different origin): captures
        // the request it receives so we can assert the credential and body were
        // not replayed to it.
        let sink_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let sink_addr = sink_listener
            .local_addr()
            .unwrap();
        let (tx, rx) = oneshot::channel::<String>();
        tokio::spawn(async move {
            let (mut sock, _) = sink_listener
                .accept()
                .await
                .unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock
                .read(&mut buf)
                .await
                .unwrap_or(0);
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
                .await;
            let _ = sock.flush().await;
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
        });

        // Entry server: redirects cross-origin to the sink server.
        let entry_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let entry_addr = entry_listener
            .local_addr()
            .unwrap();
        let sink_url = format!("http://{sink_addr}/sink");
        let redirect = format!("HTTP/1.1 302 Found\r\nLocation: {sink_url}\r\nContent-Length: 0\r\n\r\n");
        tokio::spawn(async move {
            let (mut sock, _) = entry_listener
                .accept()
                .await
                .unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let _ = sock
                .write_all(redirect.as_bytes())
                .await;
            let _ = sock.flush().await;
        });

        let entry_url = format!("http://{entry_addr}/start");
        let allow = format!("{entry_url},{sink_url}");

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer super-secret"
                .parse()
                .unwrap(),
        );

        let resp = guarded_send_inner(
            Method::POST,
            &entry_url,
            headers,
            Some(b"secret-body".to_vec()),
            EgressPolicy::Strict,
            Duration::from_secs(5),
            Some(&allow),
        )
        .await
        .expect("cross-origin redirect should complete");
        assert_eq!(resp.status(), 200);

        let received = rx
            .await
            .expect("sink server must capture the redirected request");
        let lower = received.to_ascii_lowercase();
        assert!(!lower.contains("authorization"), "Authorization must be stripped cross-origin, got:\n{received}");
        assert!(!received.contains("secret-body"), "request body must be dropped cross-origin, got:\n{received}");
    }

    #[test]
    fn pinned_forward_client_pins_loopback_and_rfc1918() {
        let (_loop_client, loop_target) =
            pinned_forward_client("http://127.0.0.1:9/ok", Duration::from_secs(5)).expect("loopback forward must pin");
        assert_eq!(loop_target.host, "127.0.0.1");
        assert_eq!(loop_target.addrs, vec!["127.0.0.1:9".parse().unwrap()]);

        let (_priv_client, priv_target) = pinned_forward_client("http://10.0.0.1:8080/api", Duration::from_secs(5))
            .expect("RFC1918 forward must pin");
        assert_eq!(priv_target.host, "10.0.0.1");
        assert_eq!(
            priv_target.addrs,
            vec![
                "10.0.0.1:8080"
                    .parse()
                    .unwrap()
            ]
        );
    }

    #[test]
    fn pinned_forward_client_blocks_cloud_metadata_only() {
        for raw in ["http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/computeMetadata/v1/"] {
            let result = pinned_forward_client(raw, Duration::from_secs(5));
            assert!(matches!(result, Err(EgressError::Blocked(_))), "metadata must be blocked: {raw}, got {result:?}");
        }
    }

    #[tokio::test]
    async fn pinned_forward_client_returns_redirect_without_following() {
        let addr =
            spawn_server("HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\n\r\n").await;
        let url = format!("http://{addr}/start");

        let (client, target) = pinned_forward_client(&url, Duration::from_secs(5)).expect("loopback forward must pin");
        // Pinned to the exact vetted address — a later re-resolution cannot move it.
        assert_eq!(target.addrs, vec![addr]);

        let resp = client
            .get(&url)
            .send()
            .await
            .expect("pinned forward GET must reach the loopback server");

        // Redirects are disabled: the 3xx is returned as-is, not followed to the
        // metadata Location.
        assert_eq!(resp.status(), 302);
        assert_eq!(
            resp.headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("http://169.254.169.254/")
        );
    }

    #[test]
    fn pinned_strict_client_pins_public_target() {
        let (_client, target) =
            pinned_strict_client("https://1.2.3.4:443/mcp", Duration::from_secs(5)).expect("public target must pin");
        assert_eq!(target.host, "1.2.3.4");
        assert_eq!(target.addrs, vec!["1.2.3.4:443".parse().unwrap()]);
    }

    #[test]
    fn pinned_strict_client_blocks_loopback_rfc1918_and_metadata() {
        // Unlike `pinned_forward_client`, Strict blocks loopback and RFC 1918 too.
        for raw in ["http://127.0.0.1:8080/mcp", "http://10.0.0.1/mcp", "http://169.254.169.254/latest/meta-data/"] {
            let result = pinned_strict_client(raw, Duration::from_secs(5));
            assert!(matches!(result, Err(EgressError::Blocked(_))), "strict must block: {raw}, got {result:?}");
        }
    }

    #[tokio::test]
    async fn pinned_client_disables_redirects() {
        // Exercise the redirect-disabled pinned client `pinned_client` builds
        // via the shared `pin_and_build` path against an allow-listed loopback
        // server; a 3xx is returned rather than followed.
        let addr =
            spawn_server("HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\n\r\n").await;
        let target = PinnedTarget {
            url: format!("http://{addr}/start")
                .parse()
                .unwrap(),
            host: addr.ip().to_string(),
            addrs: vec![addr],
        };
        let client = pinned_client(&target, Duration::from_secs(5)).expect("pinned client must build");

        let resp = client
            .get(target.url.clone())
            .send()
            .await
            .expect("pinned GET must reach the loopback server");

        // Redirects disabled: the 3xx is returned as-is, not followed to metadata.
        assert_eq!(resp.status(), 302);
        assert_eq!(
            resp.headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("http://169.254.169.254/")
        );
    }
}
