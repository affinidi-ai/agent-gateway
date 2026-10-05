use url::{Host, Url};

/// Well-known cloud-provider metadata service IPv4 addresses.
/// These must never be reachable through user-supplied URLs.
const CLOUD_METADATA_IPV4: &[std::net::Ipv4Addr] = &[
    // AWS / GCP / Azure / DigitalOcean / OpenStack / HP Helion
    std::net::Ipv4Addr::new(169, 254, 169, 254),
    // AWS ECS task metadata
    std::net::Ipv4Addr::new(169, 254, 170, 2),
    // Oracle Cloud
    std::net::Ipv4Addr::new(192, 0, 0, 192),
    // Alibaba Cloud
    std::net::Ipv4Addr::new(100, 100, 100, 200),
];

/// Well-known cloud-provider metadata service IPv6 addresses.
const CLOUD_METADATA_IPV6: &[std::net::Ipv6Addr] = &[
    // AWS EC2 IPv6 metadata endpoint
    std::net::Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254),
];

/// Hostnames used by cloud providers for metadata services.
const CLOUD_METADATA_HOSTNAMES: &[&str] = &["metadata.google.internal", "metadata"];

/// Returns `true` if `ip` is a loopback or unspecified address.
fn is_loopback_or_unspecified_v4(ip: std::net::Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_unspecified()
}

/// Returns `true` if `ip` is a loopback or unspecified IPv6 address.
fn is_loopback_or_unspecified_v6(ip: std::net::Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unspecified()
}

/// Returns `true` if the given IPv4 address is a cloud metadata endpoint.
fn is_cloud_metadata_v4(ip: std::net::Ipv4Addr) -> bool {
    CLOUD_METADATA_IPV4.contains(&ip)
}

/// Returns `true` if the given IPv6 address is a cloud metadata endpoint,
/// including IPv4-mapped forms (e.g. `::ffff:169.254.169.254`).
fn is_cloud_metadata_v6(ip: std::net::Ipv6Addr) -> bool {
    if CLOUD_METADATA_IPV6.contains(&ip) {
        return true;
    }
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_cloud_metadata_v4(mapped);
    }
    false
}

/// Returns `true` if the hostname matches a cloud metadata hostname.
fn is_cloud_metadata_hostname(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h
        .strip_suffix('.')
        .unwrap_or(&h);
    CLOUD_METADATA_HOSTNAMES
        .iter()
        .any(|blocked| *h == **blocked)
}

/// Returns `true` if the parsed URL host is a cloud metadata endpoint.
/// Does NOT block loopback — suitable for the forwarding layer where
/// localhost targets are legitimate in dev/test.
fn is_cloud_metadata_host(host: &Host<&str>) -> bool {
    match host {
        Host::Ipv4(ip) => is_cloud_metadata_v4(*ip),
        Host::Ipv6(ip) => is_cloud_metadata_v6(*ip),
        Host::Domain(domain) => is_cloud_metadata_hostname(domain),
    }
}

/// Returns `true` if the parsed URL host is a cloud metadata endpoint
/// OR a loopback/unspecified address. Used at ingestion time (API handlers).
fn is_blocked_host(host: &Host<&str>) -> bool {
    if is_cloud_metadata_host(host) {
        return true;
    }
    match host {
        Host::Ipv4(ip) => is_loopback_or_unspecified_v4(*ip),
        Host::Ipv6(ip) => {
            if is_loopback_or_unspecified_v6(*ip) {
                return true;
            }
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_loopback_or_unspecified_v4(mapped);
            }
            false
        }
        Host::Domain(domain) => {
            let h = domain.to_ascii_lowercase();
            let h = h
                .strip_suffix('.')
                .unwrap_or(&h);
            h == "localhost" || h.ends_with(".localhost")
        }
    }
}

/// Validate that a URL does not point to a cloud-provider metadata service or
/// loopback address.
///
/// Accepts `http://` and `https://` URLs to private RFC 1918 ranges (same-VPC
/// agent traffic is legitimate). Only blocks:
///   - Cloud metadata IPs (AWS, GCP, Azure, Oracle, Alibaba, DigitalOcean, …)
///   - Cloud metadata hostnames (`metadata.google.internal`, `metadata`)
///   - Loopback / unspecified addresses (`127.x`, `localhost`, `::1`, `0.0.0.0`)
///   - Embedded credentials (`user:pass@host`)
///
/// Returns the parsed [`Url`] on success, or a human-readable error string.
pub fn validate_url_not_cloud_metadata(raw: &str) -> Result<Url, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("URL must not be empty".into());
    }

    let parsed = Url::parse(trimmed).map_err(|e| format!("Invalid URL '{}': {}", trimmed, e))?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(format!("URL scheme must be http or https, got '{}'", scheme));
    }

    if parsed.host().is_none() {
        return Err("URL must include a host".into());
    }

    if parsed
        .host_str()
        .is_some_and(|h| h.is_empty())
    {
        return Err("URL must include a host".into());
    }

    // Reject embedded credentials
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("URL must not contain embedded credentials".into());
    }

    let host = parsed.host().unwrap(); // safe: checked above

    if is_blocked_host(&host) {
        return Err(format!(
            "URL host '{}' is blocked: cloud-provider metadata services and loopback addresses \
             are not allowed as target endpoints",
            host
        ));
    }

    Ok(parsed)
}

/// Returns `true` if the resolved `IpAddr` is a cloud-provider metadata
/// endpoint (including IPv4-mapped forms), ignoring loopback / private ranges.
///
/// Metadata is the one class that is *never* relaxed by any egress policy or
/// test allow-list, so [`crate::egress`] vets allow-listed targets through this.
pub(crate) fn is_cloud_metadata_resolved_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_cloud_metadata_v4(v4),
        std::net::IpAddr::V6(v6) => {
            is_cloud_metadata_v6(v6)
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(is_cloud_metadata_v4)
        }
    }
}

/// Returns `true` if the resolved `IpAddr` must be blocked.
///
/// Matches the same policy as [`is_blocked_host`] but operates on a concrete
/// `IpAddr` obtained from DNS resolution rather than the raw URL host token.
pub(crate) fn is_blocked_resolved_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_cloud_metadata_v4(v4) || is_loopback_or_unspecified_v4(v4),
        std::net::IpAddr::V6(v6) => {
            if is_cloud_metadata_v6(v6) || is_loopback_or_unspecified_v6(v6) {
                return true;
            }
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_cloud_metadata_v4(mapped) || is_loopback_or_unspecified_v4(mapped);
            }
            false
        }
    }
}

/// Shared implementation for DNS-aware URL validation.
///
/// When `block_loopback` is `true` the behaviour matches [`validate_resolved_url`]:
/// loopback and unspecified addresses are rejected both statically and after DNS
/// resolution.  When `false` only cloud-provider metadata endpoints are blocked,
/// and loopback / RFC 1918 are allowed — see [`validate_resolved_cloud_metadata_url`].
fn validate_resolved_url_inner(
    raw: &str,
    block_loopback: bool,
) -> Result<Url, String> {
    let parsed = if block_loopback {
        validate_url_not_cloud_metadata(raw)?
    } else {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("URL must not be empty".into());
        }
        let p = Url::parse(trimmed).map_err(|e| format!("Invalid URL '{}': {}", trimmed, e))?;
        let scheme = p.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(format!("URL scheme must be http or https, got '{}'", scheme));
        }
        if p.host().is_none()
            || p.host_str()
                .is_some_and(|h| h.is_empty())
        {
            return Err("URL must include a host".into());
        }
        if !p.username().is_empty() || p.password().is_some() {
            return Err("URL must not contain embedded credentials".into());
        }
        let host = p.host().unwrap();
        if is_cloud_metadata_host(&host) {
            return Err(format!(
                "URL host '{}' is blocked: cloud-provider metadata services are not allowed \
                 as target endpoints",
                host
            ));
        }
        p
    };

    // IP literals were already validated statically — no DNS to do.
    if matches!(parsed.host(), Some(Host::Ipv4(_) | Host::Ipv6(_))) {
        return Ok(parsed);
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL must include a host".to_string())?;
    let port = parsed
        .port_or_known_default()
        .unwrap_or(80);

    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for '{}': {}", host, e))?
        .collect();

    if addrs.is_empty() {
        return Err(format!("DNS resolution for '{}' returned no addresses", host));
    }

    for socket_addr in addrs {
        let ip = socket_addr.ip();
        let blocked = if block_loopback {
            is_blocked_resolved_ip(ip)
        } else {
            match ip {
                std::net::IpAddr::V4(v4) => is_cloud_metadata_v4(v4),
                std::net::IpAddr::V6(v6) => {
                    if is_cloud_metadata_v6(v6) {
                        true
                    } else {
                        v6.to_ipv4_mapped()
                            .is_some_and(is_cloud_metadata_v4)
                    }
                }
            }
        };
        if blocked {
            let reason = if block_loopback {
                "cloud-provider metadata services and loopback addresses are not allowed as target endpoints"
            } else {
                "cloud-provider metadata services are not allowed as target endpoints"
            };
            return Err(format!("URL host '{}' resolves to blocked address '{}': {}", host, ip, reason));
        }
    }

    Ok(parsed)
}

/// Validate a URL and then verify that every address it resolves to is safe.
///
/// Defense-in-depth layer on top of [`validate_url_not_cloud_metadata`] that
/// guards against DNS rebinding attacks: a hostname that passes the static check
/// could still resolve to a blocked address.
///
/// - Runs [`validate_url_not_cloud_metadata`] first; propagates its error unchanged.
/// - Skips DNS resolution for IP literals (already validated statically).
/// - Resolves the hostname via [`std::net::ToSocketAddrs`] (blocking OS call).
/// - Rejects if **any** resolved address is a cloud metadata endpoint, loopback,
///   or unspecified address.
/// - DNS failures (NXDOMAIN, timeout, …) are returned as errors.
///
/// Returns the parsed [`Url`] on success, or a human-readable error string.
pub fn validate_resolved_url(raw: &str) -> Result<Url, String> {
    validate_resolved_url_inner(raw, true)
}

/// Validate a URL and verify that every address it resolves to is not a
/// cloud-provider metadata endpoint.
///
/// Like [`validate_resolved_url`] but intentionally allows loopback and
/// RFC 1918 private ranges. Use this for admin-configured JWKS URIs and other
/// endpoints where same-machine or same-VPC access is legitimate, but DNS
/// rebinding to a cloud metadata endpoint must still be prevented.
///
/// Blocks: cloud metadata IPs/hostnames (static + DNS), embedded credentials,
/// non-http(s) schemes.
/// Allows: loopback, RFC 1918 private ranges.
///
/// Returns the parsed [`Url`] on success, or a human-readable error string.
pub fn validate_resolved_cloud_metadata_url(raw: &str) -> Result<Url, String> {
    validate_resolved_url_inner(raw, false)
}

fn bdd_oauth_endpoint_allowlist() -> Option<String> {
    if std::env::var("AG_TEST_MODE").as_deref() != Ok("true") {
        return None;
    }
    std::env::var("AG_BDD_OAUTH_ENDPOINT_ALLOWLIST")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn parse_oauth_endpoint_allowlist(raw: &str) -> Result<Vec<Url>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(validate_resolved_cloud_metadata_url)
        .collect()
}

fn validate_oauth_endpoint_url_inner(
    raw: &str,
    exact_allowlist: Option<&str>,
) -> Result<Url, String> {
    match validate_resolved_url(raw) {
        Ok(url) => Ok(url),
        Err(production_error) => {
            let Some(allowlist_raw) = exact_allowlist else {
                return Err(production_error);
            };
            let candidate = validate_resolved_cloud_metadata_url(raw)?;
            let allowed = parse_oauth_endpoint_allowlist(allowlist_raw)?;
            if allowed
                .iter()
                .any(|entry| entry == &candidate)
            {
                Ok(candidate)
            } else {
                Err(format!(
                    "{}; OAuth endpoint '{}' is not in the BDD exact endpoint allowlist",
                    production_error, candidate
                ))
            }
        }
    }
}

/// Validate an OAuth endpoint URL used by credential delegation.
///
/// Production behavior matches [`validate_resolved_url`]: cloud metadata,
/// loopback, unspecified hosts, bad schemes, embedded credentials, and DNS
/// rebinding to blocked addresses are rejected. BDD real-process tests may set
/// `AG_TEST_MODE=true` with `AG_BDD_OAUTH_ENDPOINT_ALLOWLIST` containing exact
/// loopback endpoint URLs generated by the harness. The allowlist remains exact
/// and still blocks cloud metadata endpoints.
pub fn validate_oauth_endpoint_url(raw: &str) -> Result<Url, String> {
    validate_oauth_endpoint_url_inner(raw, bdd_oauth_endpoint_allowlist().as_deref())
}

/// Defense-in-depth check for the forwarding layer. Only blocks cloud metadata
/// endpoints — does NOT block loopback (channels may legitimately target
/// localhost in dev/test environments).
pub fn reject_cloud_metadata_url(raw: &str) -> Result<(), String> {
    let parsed = match Url::parse(raw) {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };

    if let Some(host) = parsed.host()
        && is_cloud_metadata_host(&host)
    {
        return Err(format!(
            "URL host '{}' is blocked: cloud-provider metadata services \
                 are not allowed as target endpoints",
            host
        ));
    }

    Ok(())
}

/// Returns `true` if the IPv4 address is in an RFC 1918 private range
/// or the full 169.254/16 link-local range.
fn is_private_or_link_local_v4(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    matches!(
        (a, b),
        // RFC 1918
        (10, _)
        | (172, 16..=31)
        | (192, 168)
        // Full link-local (169.254/16)
        | (169, 254)
    )
}

/// Returns `true` if the IPv6 address is in a range that must not be
/// reachable from a webhook-style outbound call:
/// - Unique-local (fc00::/7)
/// - Link-local (fe80::/10)
/// - IPv4-mapped private/link-local
fn is_private_or_link_local_v6(ip: std::net::Ipv6Addr) -> bool {
    let [a, b, ..] = ip.octets();
    // fc00::/7 (unique-local)
    if a & 0xfe == 0xfc {
        return true;
    }
    // fe80::/10 (link-local)
    if a == 0xfe && (b & 0xc0) == 0x80 {
        return true;
    }
    // IPv4-mapped (::ffff:x.x.x.x)
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_private_or_link_local_v4(mapped);
    }
    false
}

/// Strict SSRF validator for webhook-style outbound endpoints
/// (X402Proxy, MppProxy, Slack webhooks, …).
///
/// Rejects everything `validate_url_not_cloud_metadata` rejects, and also
/// blocks all private network ranges that have no legitimate use in an
/// externally-reachable payment / webhook target:
///
/// - RFC 1918 private ranges (10/8, 172.16/12, 192.168/16)
/// - Full IPv4 link-local (169.254/16, including metadata IPs)
/// - IPv6 unique-local (fc00::/7)
/// - IPv6 link-local (fe80::/10)
/// - IPv4-mapped forms of any of the above
///
/// Returns the parsed [`Url`] on success, or a human-readable error string.
pub fn validate_webhook_url(raw: &str) -> Result<Url, String> {
    // Run the base check first (cloud metadata + loopback + scheme + credentials)
    let parsed = validate_url_not_cloud_metadata(raw)?;

    let host = parsed.host().unwrap(); // safe: validate_url_not_cloud_metadata verified host exists

    let blocked = match &host {
        Host::Ipv4(ip) => is_private_or_link_local_v4(*ip),
        Host::Ipv6(ip) => is_private_or_link_local_v6(*ip),
        Host::Domain(_) => false,
    };

    if blocked {
        return Err(format!(
            "URL host '{}' is blocked: private and link-local addresses \
             are not allowed as webhook or payment proxy endpoints",
            host
        ));
    }

    Ok(parsed)
}

/// Returns `true` if the resolved `IpAddr` must be blocked for a webhook target.
///
/// Combines the base block-list of [`is_blocked_resolved_ip`] (cloud metadata +
/// loopback) with the private/link-local ranges that have no legitimate use for
/// externally-reachable webhook endpoints.
pub(crate) fn is_blocked_resolved_webhook_ip(ip: std::net::IpAddr) -> bool {
    if is_blocked_resolved_ip(ip) {
        return true;
    }
    match ip {
        std::net::IpAddr::V4(v4) => is_private_or_link_local_v4(v4),
        std::net::IpAddr::V6(v6) => {
            if is_private_or_link_local_v6(v6) {
                return true;
            }
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_private_or_link_local_v4(mapped);
            }
            false
        }
    }
}

/// DNS-aware strict SSRF validator for webhook-style outbound endpoints.
///
/// Combines [`validate_webhook_url`] (static checks) with DNS resolution,
/// closing the gap where a domain passes static checks but resolves to a
/// private or cloud-metadata address (DNS rebinding / split-horizon attack).
///
/// Blocks everything [`validate_webhook_url`] blocks, plus any domain that
/// resolves to:
/// - Cloud metadata IPs / hostnames
/// - Loopback / unspecified addresses
/// - RFC 1918 private ranges (10/8, 172.16/12, 192.168/16)
/// - Full IPv4 link-local (169.254/16)
/// - IPv6 unique-local (fc00::/7) and link-local (fe80::/10)
/// - IPv4-mapped forms of any of the above
///
/// DNS failures (NXDOMAIN, timeout, empty response) are returned as errors.
///
/// Returns the parsed [`Url`] on success, or a human-readable error string.
pub fn validate_resolved_webhook_url(raw: &str) -> Result<Url, String> {
    // Static checks first (IP literals, scheme, credentials, private ranges).
    let parsed = validate_webhook_url(raw)?;

    // IP literals were fully validated statically — no DNS needed.
    if matches!(parsed.host(), Some(Host::Ipv4(_) | Host::Ipv6(_))) {
        return Ok(parsed);
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL must include a host".to_string())?;
    let port = parsed
        .port_or_known_default()
        .unwrap_or(80);

    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for '{}': {}", host, e))?
        .collect();

    if addrs.is_empty() {
        return Err(format!("DNS resolution for '{}' returned no addresses", host));
    }

    for socket_addr in addrs {
        let ip = socket_addr.ip();
        if is_blocked_resolved_webhook_ip(ip) {
            return Err(format!(
                "URL host '{}' resolves to blocked address '{}': private, link-local, and \
                 cloud-provider metadata addresses are not allowed as webhook endpoints",
                host, ip
            ));
        }
    }

    Ok(parsed)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────

    fn must_block(url: &str) {
        let result = validate_url_not_cloud_metadata(url);
        assert!(result.is_err(), "Expected '{}' to be blocked, but it was allowed", url);
    }

    fn must_allow(url: &str) {
        let result = validate_url_not_cloud_metadata(url);
        assert!(result.is_ok(), "Expected '{}' to be allowed, but got error: {}", url, result.unwrap_err());
    }

    // ── Cloud metadata IPs ──────────────────────────────────────────────

    #[test]
    fn blocks_aws_metadata_ip() {
        must_block("http://169.254.169.254/latest/meta-data/");
        must_block("https://169.254.169.254/");
        must_block("http://169.254.169.254:80/");
    }

    #[test]
    fn blocks_aws_ecs_metadata_ip() {
        must_block("http://169.254.170.2/v2/credentials/uid");
    }

    #[test]
    fn blocks_oracle_cloud_metadata_ip() {
        must_block("http://192.0.0.192/latest/");
        must_block("http://192.0.0.192/latest/meta-data/");
    }

    #[test]
    fn blocks_alibaba_cloud_metadata_ip() {
        must_block("http://100.100.100.200/latest/meta-data/");
        must_block("http://100.100.100.200/latest/meta-data/instance-id");
    }

    #[test]
    fn blocks_aws_ipv6_metadata() {
        must_block("http://[fd00:ec2::254]/latest/meta-data/");
    }

    // ── Cloud metadata hostnames ────────────────────────────────────────

    #[test]
    fn blocks_gcp_metadata_hostname() {
        must_block("http://metadata.google.internal/computeMetadata/v1/");
        must_block("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token");
    }

    #[test]
    fn blocks_gcp_metadata_short_hostname() {
        must_block("http://metadata/computeMetadata/v1/");
    }

    #[test]
    fn blocks_gcp_metadata_case_insensitive() {
        must_block("http://Metadata.Google.Internal/computeMetadata/v1/");
        must_block("http://METADATA/computeMetadata/v1/");
    }

    // ── Loopback / unspecified ──────────────────────────────────────────

    #[test]
    fn blocks_localhost() {
        must_block("http://localhost/");
        must_block("http://localhost:8080/api");
        must_block("http://sub.localhost/");
    }

    #[test]
    fn blocks_ipv4_loopback() {
        must_block("http://127.0.0.1/");
        must_block("http://127.0.0.1:3000/");
        must_block("http://127.255.255.255/");
    }

    #[test]
    fn blocks_ipv6_loopback() {
        must_block("http://[::1]/");
        must_block("http://[::1]:8080/");
    }

    #[test]
    fn blocks_unspecified() {
        must_block("http://0.0.0.0/");
        must_block("http://[::]/");
    }

    // ── IPv4-mapped IPv6 ────────────────────────────────────────────────

    #[test]
    fn blocks_ipv4_mapped_metadata() {
        must_block("http://[::ffff:169.254.169.254]/");
        must_block("http://[::ffff:127.0.0.1]/");
        must_block("http://[::ffff:192.0.0.192]/");
        must_block("http://[::ffff:100.100.100.200]/");
    }

    // ── Numeric obfuscation (url crate normalizes to dotted-decimal) ───

    #[test]
    fn blocks_decimal_integer_metadata_ip() {
        // 169.254.169.254 == 2852039166 in decimal
        // The `url` crate parses http://2852039166/ as http://169.254.169.254/
        must_block("http://2852039166/latest/meta-data/");
    }

    #[test]
    fn blocks_hex_metadata_ip() {
        // 169.254.169.254 == 0xa9fea9fe
        must_block("http://0xa9fea9fe/latest/meta-data/");
    }

    #[test]
    fn blocks_octal_metadata_ip() {
        // 169.254.169.254 in octal = 0251.0376.0251.0376
        must_block("http://0251.0376.0251.0376/");
    }

    #[test]
    fn blocks_decimal_loopback() {
        // 127.0.0.1 == 2130706433
        must_block("http://2130706433/");
    }

    // ── Private RFC 1918 IPs MUST pass ──────────────────────────────────

    #[test]
    fn allows_rfc1918_class_a() {
        must_allow("http://10.0.1.5/api/v1/agent");
        must_allow("http://10.255.255.255:8080/");
    }

    #[test]
    fn allows_rfc1918_class_b() {
        must_allow("http://172.16.0.1/");
        must_allow("http://172.20.0.1:3000/");
        must_allow("http://172.31.255.255/");
    }

    #[test]
    fn allows_rfc1918_class_c() {
        must_allow("http://192.168.1.1/");
        must_allow("http://192.168.0.100:443/");
    }

    // ── Public URLs MUST pass ───────────────────────────────────────────

    #[test]
    fn allows_public_urls() {
        must_allow("https://api.example.com/v1/agent");
        must_allow("http://my-agent.internal.company.io:8080/");
        must_allow("https://1.2.3.4/api");
    }

    #[test]
    fn allows_http_scheme() {
        must_allow("http://agent.vpc.local:8000/");
    }

    // ── Embedded credentials blocked ────────────────────────────────────

    #[test]
    fn blocks_embedded_credentials() {
        must_block("http://user:pass@example.com/");
        must_block("https://admin:secret@10.0.0.1/");
    }

    // ── Misc edge cases ─────────────────────────────────────────────────

    #[test]
    fn rejects_empty_url() {
        must_block("");
        must_block("   ");
    }

    #[test]
    fn rejects_non_http_schemes() {
        must_block("ftp://example.com/");
        must_block("file:///etc/passwd");
        must_block("gopher://evil.com/");
    }

    #[test]
    fn allows_non_metadata_link_local() {
        // 169.254.x.x that are NOT 169.254.169.254 or 169.254.170.2
        // are link-local but not metadata — we allow them since the goal
        // is blocking cloud metadata, not all link-local traffic.
        must_allow("http://169.254.1.1/");
    }

    #[test]
    fn oauth_endpoint_blocks_loopback_by_default() {
        let result = validate_oauth_endpoint_url_inner("http://127.0.0.1:8080/token", None);
        assert!(result.is_err(), "expected OAuth endpoint loopback URL to be blocked by default");
    }

    #[test]
    fn oauth_endpoint_allows_exact_bdd_allowlist_match() {
        let result = validate_oauth_endpoint_url_inner(
            "http://127.0.0.1:8080/token",
            Some("http://127.0.0.1:8080/authorize,http://127.0.0.1:8080/token"),
        );
        assert!(result.is_ok(), "expected exact BDD OAuth endpoint URL to be allowed: {result:?}");
    }

    #[test]
    fn oauth_endpoint_rejects_loopback_not_in_exact_bdd_allowlist() {
        let result = validate_oauth_endpoint_url_inner(
            "http://127.0.0.1:8081/token",
            Some("http://127.0.0.1:8080/authorize,http://127.0.0.1:8080/token"),
        );
        assert!(result.is_err(), "expected non-allowlisted OAuth endpoint URL to be blocked");
    }

    #[test]
    fn oauth_endpoint_still_blocks_cloud_metadata_for_bdd_allowlist() {
        let result = validate_oauth_endpoint_url_inner(
            "http://169.254.169.254/latest/meta-data/",
            Some("http://169.254.169.254/latest/meta-data/"),
        );
        assert!(result.is_err(), "expected BDD OAuth endpoint cloud metadata URL to stay blocked");
    }

    // ── Forwarding layer (reject_cloud_metadata_url) ────────────────────

    fn forwarding_must_block(url: &str) {
        let result = reject_cloud_metadata_url(url);
        assert!(result.is_err(), "Expected '{}' to be blocked at forwarding, but it was allowed", url);
    }

    fn forwarding_must_allow(url: &str) {
        let result = reject_cloud_metadata_url(url);
        assert!(
            result.is_ok(),
            "Expected '{}' to be allowed at forwarding, but got error: {}",
            url,
            result.unwrap_err()
        );
    }

    #[test]
    fn forwarding_blocks_metadata_ips() {
        forwarding_must_block("http://169.254.169.254/latest/meta-data/");
        forwarding_must_block("http://192.0.0.192/latest/");
        forwarding_must_block("http://100.100.100.200/latest/meta-data/");
        forwarding_must_block("http://metadata.google.internal/computeMetadata/v1/");
        forwarding_must_block("http://[fd00:ec2::254]/latest/meta-data/");
    }

    #[test]
    fn forwarding_allows_localhost() {
        forwarding_must_allow("http://127.0.0.1:8080/sse");
        forwarding_must_allow("http://localhost:3000/api");
        forwarding_must_allow("http://[::1]:8080/");
    }

    #[test]
    fn forwarding_allows_private_ips() {
        forwarding_must_allow("http://10.0.1.5/api");
        forwarding_must_allow("http://192.168.1.1:8080/");
    }

    // ── DNS-aware forwarding guard (validate_resolved_cloud_metadata_url) ──
    // The proxy-forward sinks (proxy/handler.rs, proxy/outbound_handler.rs) now
    // use this validator: fail-closed on a bad URL, block a host that resolves to
    // cloud metadata, but still allow the operator-configured loopback / RFC 1918
    // forwards that the static `reject_cloud_metadata_url` used to permit.

    #[test]
    fn resolved_forwarding_guard_fails_closed_on_unparseable_url() {
        // `reject_cloud_metadata_url` returned Ok(()) here (fail-open); the new
        // guard must reject.
        assert!(validate_resolved_cloud_metadata_url("not a url").is_err());
        assert!(validate_resolved_cloud_metadata_url("").is_err());
        assert!(validate_resolved_cloud_metadata_url("ftp://example.com/").is_err());
    }

    #[test]
    fn resolved_forwarding_guard_blocks_metadata_literals() {
        assert!(validate_resolved_cloud_metadata_url("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(validate_resolved_cloud_metadata_url("http://metadata.google.internal/computeMetadata/v1/").is_err());
    }

    #[test]
    fn resolved_forwarding_guard_allows_loopback_and_private() {
        // Operator-configured localhost sidecars / same-VPC upstreams must still work.
        assert!(validate_resolved_cloud_metadata_url("http://127.0.0.1:8080/sse").is_ok());
        assert!(validate_resolved_cloud_metadata_url("http://10.0.1.5/api").is_ok());
        assert!(validate_resolved_cloud_metadata_url("http://192.168.1.1:8080/").is_ok());
    }

    // ── Trailing-dot FQDN bypass ────────────────────────────────────────

    #[test]
    fn blocks_trailing_dot_metadata_hostname() {
        must_block("http://metadata.google.internal./computeMetadata/v1/");
        must_block("http://metadata./computeMetadata/v1/");
        must_block("http://Metadata.Google.Internal./computeMetadata/v1/");
    }

    #[test]
    fn blocks_trailing_dot_localhost() {
        must_block("http://localhost./");
        must_block("http://LOCALHOST./");
        must_block("http://sub.localhost./");
    }

    #[test]
    fn forwarding_blocks_trailing_dot_metadata() {
        forwarding_must_block("http://metadata.google.internal./computeMetadata/v1/");
        forwarding_must_block("http://metadata./computeMetadata/v1/");
        forwarding_must_block("http://Metadata.Google.Internal./");
    }

    // ── validate_webhook_url ─────────────────────────────────────────────────

    fn webhook_must_block(url: &str) {
        let result = validate_webhook_url(url);
        assert!(result.is_err(), "Expected webhook '{}' to be blocked, but it was allowed", url);
    }

    fn webhook_must_allow(url: &str) {
        let result = validate_webhook_url(url);
        assert!(result.is_ok(), "Expected webhook '{}' to be allowed, but got error: {}", url, result.unwrap_err());
    }

    #[test]
    fn webhook_blocks_rfc1918_class_a() {
        webhook_must_block("http://10.0.0.1/pay");
        webhook_must_block("http://10.255.255.255:8080/api");
    }

    #[test]
    fn webhook_blocks_rfc1918_class_b() {
        webhook_must_block("http://172.16.0.1/pay");
        webhook_must_block("http://172.31.255.255/api");
    }

    #[test]
    fn webhook_blocks_rfc1918_class_c() {
        webhook_must_block("http://192.168.1.100/pay");
        webhook_must_block("http://192.168.0.1:443/");
    }

    #[test]
    fn webhook_blocks_full_link_local_range() {
        webhook_must_block("http://169.254.1.1/");
        webhook_must_block("http://169.254.169.254/latest/meta-data/");
        webhook_must_block("http://169.254.170.2/v2/credentials/");
    }

    #[test]
    fn webhook_blocks_ipv6_unique_local() {
        webhook_must_block("http://[fc00::1]/pay");
        webhook_must_block("http://[fd12:3456:789a::1]/pay");
    }

    #[test]
    fn webhook_blocks_ipv6_link_local() {
        webhook_must_block("http://[fe80::1]/pay");
        webhook_must_block("http://[fe80::1%2512]/pay");
    }

    #[test]
    fn webhook_blocks_loopback_and_metadata() {
        webhook_must_block("http://127.0.0.1/pay");
        webhook_must_block("http://localhost/pay");
        webhook_must_block("http://169.254.169.254/latest/meta-data/");
    }

    #[test]
    fn webhook_blocks_embedded_credentials() {
        webhook_must_block("http://user:pass@payments.example.com/");
    }

    #[test]
    fn webhook_blocks_non_http_schemes() {
        webhook_must_block("file:///etc/passwd");
        webhook_must_block("ftp://example.com/");
    }

    #[test]
    fn webhook_inherits_base_blocks() {
        webhook_must_block("http://169.254.169.254/latest/meta-data/");
        webhook_must_block("http://127.0.0.1/");
        webhook_must_block("http://localhost/");
        webhook_must_block("http://0.0.0.0/");
        webhook_must_block("file:///etc/passwd");
        webhook_must_block("http://user:pass@example.com/");
    }

    #[test]
    fn webhook_allows_public_urls() {
        webhook_must_allow("https://api.payments.example.com/v1/pay");
        webhook_must_allow("http://1.2.3.4/api");
        webhook_must_allow("https://payments.example.com/webhook");
        webhook_must_allow("https://hooks.slack.com/services/T00/B00/xxx");
        webhook_must_allow("http://my-webhook.example.com/hook");
    }

    #[test]
    fn webhook_blocks_ipv4_mapped_private() {
        webhook_must_block("http://[::ffff:10.0.0.1]/hook");
        webhook_must_block("http://[::ffff:192.168.1.1]/hook");
        webhook_must_block("http://[::ffff:172.16.0.1]/hook");
    }

    // ── validate_resolved_webhook_url ────────────────────────────────────────

    fn resolved_webhook_must_block(url: &str) {
        let result = validate_resolved_webhook_url(url);
        assert!(result.is_err(), "Expected resolved-webhook '{}' to be blocked, but it was allowed", url);
    }

    fn resolved_webhook_must_allow(url: &str) {
        let result = validate_resolved_webhook_url(url);
        assert!(
            result.is_ok(),
            "Expected resolved-webhook '{}' to be allowed, but got error: {}",
            url,
            result.unwrap_err()
        );
    }

    #[test]
    fn resolved_webhook_blocks_ip_literal_metadata() {
        resolved_webhook_must_block("http://169.254.169.254/latest/meta-data/");
        resolved_webhook_must_block("http://[fd00:ec2::254]/latest/meta-data/");
    }

    #[test]
    fn resolved_webhook_blocks_ip_literal_loopback() {
        resolved_webhook_must_block("http://127.0.0.1/hook");
        resolved_webhook_must_block("http://[::1]/hook");
    }

    #[test]
    fn resolved_webhook_blocks_ip_literal_private() {
        resolved_webhook_must_block("http://10.0.0.1/hook");
        resolved_webhook_must_block("http://192.168.1.1/hook");
        resolved_webhook_must_block("http://172.16.0.1/hook");
        resolved_webhook_must_block("http://[fc00::1]/hook");
        resolved_webhook_must_block("http://[fe80::1]/hook");
    }

    #[test]
    fn resolved_webhook_blocks_ip_literal_link_local() {
        resolved_webhook_must_block("http://169.254.1.1/hook");
    }

    #[test]
    fn resolved_webhook_blocks_embedded_credentials() {
        resolved_webhook_must_block("http://user:pass@payments.example.com/");
    }

    #[test]
    fn resolved_webhook_blocks_non_http_schemes() {
        resolved_webhook_must_block("file:///etc/passwd");
        resolved_webhook_must_block("ftp://example.com/");
    }

    #[test]
    fn resolved_webhook_allows_public_ip_literal() {
        resolved_webhook_must_allow("https://1.2.3.4/hook");
        resolved_webhook_must_allow("http://8.8.8.8/hook");
    }

    #[test]
    fn resolved_webhook_resolves_and_allows_public_domain() {
        // Resolves to public IPs — must pass.
        resolved_webhook_must_allow("https://example.com/hook");
    }

    #[test]
    fn resolved_webhook_rejects_localhost_domain() {
        // localhost resolves to 127.0.0.1 — blocked by base check before DNS.
        resolved_webhook_must_block("http://localhost/hook");
    }
}
