//! Rules a Target authentication setting must meet before the gateway sends its credential:
//! a header name it may set, a value format that cannot split the header, an https Target, and
//! a leg that checks who calls it.

/// Headers a Target credential may not use: those that frame the message or the connection,
/// where it would be dropped or would change how the request is framed or routed, and those the
/// gateway itself strips or sets on a request upstream (transit token, Fabric crossings, caller
/// and gateway identity, trace and mirror markers, the MCP session), where it would collide
/// with the gateway's value.
const RESERVED_HEADERS: [&str; 23] = [
    "Host",
    "Content-Length",
    "Transfer-Encoding",
    "Connection",
    "Keep-Alive",
    "Proxy-Connection",
    "Proxy-Authorization",
    "Proxy-Authenticate",
    "TE",
    "Upgrade",
    "Trailer",
    "Trailers",
    "X-Transit-Token",
    "X-Gateway-Fabric-Hops",
    "X-Caller-Did",
    "X-Caller-Identity-Source",
    "X-Caller-Dna-Uai",
    "X-Gateway-Did",
    "X-Did-Identity",
    "X-Did-Signed-Identity",
    "X-Gateway-Trace-Id",
    "X-Mirrored-Request",
    "Mcp-Session-Id",
];

/// Why a header value format is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderFormatProblem {
    /// `{value}` is missing or appears more than once.
    PlaceholderCount,
    /// CR, LF or NUL, which could end the header and start another.
    ControlCharacter,
}

/// Is `name` an HTTP field name: a non-empty token of `tchar`s (RFC 9110 section 5.6.2)?
pub fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// Do `a` and `b` name the same header, compared without regard to case or to `_` against `-`,
/// since some servers read both spellings as one?
pub fn same_header_name(
    a: &str,
    b: &str,
) -> bool {
    let fold = |byte: u8| match byte {
        b'_' => b'-',
        byte => byte.to_ascii_lowercase(),
    };
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .all(|(a, b)| fold(a) == fold(b))
}

/// The reserved header `name` names, in its canonical spelling, whatever its case and whether
/// it spells `-` as `_`.
pub fn reserved_header(name: &str) -> Option<&'static str> {
    RESERVED_HEADERS
        .into_iter()
        .find(|reserved| same_header_name(reserved, name))
}

/// What is wrong with a header value format, if anything: it must contain `{value}` exactly
/// once, and no CR, LF or NUL.
pub fn header_format_problem(format: &str) -> Option<HeaderFormatProblem> {
    if format.contains(['\r', '\n', '\0']) {
        Some(HeaderFormatProblem::ControlCharacter)
    } else if format
        .matches("{value}")
        .count()
        != 1
    {
        Some(HeaderFormatProblem::PlaceholderCount)
    } else {
        None
    }
}

/// Is `endpoint` an https URL with a host? `fabric://`, `a2a-proxy://`, `proxy://` and
/// `http://` Targets are not.
pub fn is_https_target(endpoint: &str) -> bool {
    url::Url::parse(endpoint.trim()).is_ok_and(|url| url.scheme() == "https" && url.host().is_some())
}

/// The MCP proxies whose `base_url` is an https URL, by id. A credential sent to a `proxy://`
/// Target goes to its MCP proxy's `base_url`, so `target_https` judges that URL.
#[derive(Debug, Default)]
pub struct HttpsMcpProxies(std::collections::HashSet<String>);

impl HttpsMcpProxies {
    /// The proxies among `(id, base_url)` pairs whose `base_url` is an https URL.
    pub fn from_base_urls<'a>(proxies: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        Self(
            proxies
                .into_iter()
                .filter(|(_, base_url)| is_https_target(base_url))
                .map(|(id, _)| id.to_string())
                .collect(),
        )
    }

    /// Does a credential sent to `endpoint` go over https: an https URL, or a `proxy://` Target
    /// whose MCP proxy is listed? A `proxy://` Target naming no listed proxy does not.
    pub fn sends_over_https(
        &self,
        endpoint: &str,
    ) -> bool {
        is_https_target(endpoint)
            || endpoint
                .strip_prefix("proxy://")
                .is_some_and(|proxy_id| self.0.contains(proxy_id))
    }
}

/// A rule the request path holds a Target credential to, named by its `[credential_policy]` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetCredentialRule {
    /// `target_https`: the credential goes only to an https endpoint.
    Https,
    /// `target_source_auth`: the credential goes only from a leg that checks its callers.
    SourceAuth,
}

impl TargetCredentialRule {
    pub const fn key(self) -> &'static str {
        match self {
            Self::Https => "target_https",
            Self::SourceAuth => "target_source_auth",
        }
    }
}

impl std::fmt::Display for TargetCredentialRule {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter.write_str(self.key())
    }
}

/// The rules sending a Target credential breaks: one that does not go over https, and one from
/// a leg that checks no caller, unless the request is the gateway's own (`gateway_originated`,
/// such as its agent card fetch), which has no caller to check.
pub fn broken_target_credential_rules(
    over_https: bool,
    checks_callers: bool,
    gateway_originated: bool,
) -> Vec<TargetCredentialRule> {
    let mut rules = Vec::new();
    if !over_https {
        rules.push(TargetCredentialRule::Https);
    }
    if !checks_callers && !gateway_originated {
        rules.push(TargetCredentialRule::SourceAuth);
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_over_https_from_a_checked_leg_breaks_no_rule() {
        assert!(broken_target_credential_rules(true, true, false).is_empty());
        assert!(broken_target_credential_rules(true, false, true).is_empty());
    }

    #[test]
    fn a_credential_not_over_https_breaks_target_https_even_on_the_gateways_own_request() {
        assert_eq!(broken_target_credential_rules(false, true, false), vec![TargetCredentialRule::Https]);
        assert_eq!(broken_target_credential_rules(false, false, true), vec![TargetCredentialRule::Https]);
    }

    #[test]
    fn a_caller_request_from_a_leg_that_checks_no_caller_breaks_target_source_auth() {
        assert_eq!(broken_target_credential_rules(true, false, false), vec![TargetCredentialRule::SourceAuth]);
        assert_eq!(
            broken_target_credential_rules(false, false, false),
            vec![TargetCredentialRule::Https, TargetCredentialRule::SourceAuth]
        );
    }

    #[test]
    fn a_rule_is_named_by_its_credential_policy_key() {
        assert_eq!(TargetCredentialRule::Https.to_string(), "target_https");
        assert_eq!(TargetCredentialRule::SourceAuth.to_string(), "target_source_auth");
    }

    #[test]
    fn a_header_name_is_a_non_empty_token() {
        for name in ["Authorization", "X-Api-Key", "x_custom.key", "A!#$%&'*+-.^_`|~9"] {
            assert!(is_header_name(name), "{name}");
        }
        for name in ["", "X Api", "X-Api:", "X-Api\r\n", "Ключ", "(x)", "a/b", "a\0b"] {
            assert!(!is_header_name(name), "{name:?}");
        }
    }

    #[test]
    fn reserved_headers_are_matched_whatever_their_case() {
        for (name, canonical) in [
            ("host", "Host"),
            ("CONTENT-LENGTH", "Content-Length"),
            ("transfer-encoding", "Transfer-Encoding"),
            ("Connection", "Connection"),
            ("keep-alive", "Keep-Alive"),
            ("proxy-connection", "Proxy-Connection"),
            ("te", "TE"),
            ("upgrade", "Upgrade"),
            ("trailer", "Trailer"),
        ] {
            assert_eq!(reserved_header(name), Some(canonical), "{name}");
        }
        for (name, canonical) in [
            ("x-transit-token", "X-Transit-Token"),
            ("X-GATEWAY-FABRIC-HOPS", "X-Gateway-Fabric-Hops"),
            ("proxy-authorization", "Proxy-Authorization"),
            ("x-caller-did", "X-Caller-Did"),
            ("x-gateway-trace-id", "X-Gateway-Trace-Id"),
            ("x-mirrored-request", "X-Mirrored-Request"),
            ("mcp-session-id", "Mcp-Session-Id"),
        ] {
            assert_eq!(reserved_header(name), Some(canonical), "{name}");
        }
        for name in ["Authorization", "X-Api-Key", "Hosts", "Content-Type", "X-Caller", "X-Gateway-Tenant"] {
            assert_eq!(reserved_header(name), None, "{name}");
        }
    }

    #[test]
    fn a_reserved_header_spelled_with_underscores_is_still_reserved() {
        for (name, canonical) in [
            ("X_Transit_Token", "X-Transit-Token"),
            ("x_caller_did", "X-Caller-Did"),
            ("Content_Length", "Content-Length"),
            ("Mcp_Session_Id", "Mcp-Session-Id"),
        ] {
            assert_eq!(reserved_header(name), Some(canonical), "{name}");
        }
        for name in ["X__Transit-Token", "X_Transit_Tokens", "XTransitToken"] {
            assert_eq!(reserved_header(name), None, "{name}");
        }
    }

    #[test]
    fn header_names_match_without_regard_to_case_or_underscore_for_hyphen() {
        for (a, b) in [("X-Api-Key", "x_api_key"), ("X_User_Token", "X-USER-TOKEN"), ("Authorization", "authorization")]
        {
            assert!(same_header_name(a, b), "{a} {b}");
        }
        for (a, b) in [("X-Api-Key", "X-Api-Keys"), ("X-Api-Key", "XApiKey"), ("X-Api-Key", "X.Api.Key"), ("", "X")] {
            assert!(!same_header_name(a, b), "{a} {b}");
        }
    }

    #[test]
    fn every_header_the_request_path_strips_or_sets_itself_is_reserved() {
        let stripped = [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
            "content-length",
            "host",
            "x-transit-token",
            crate::proxy::fabric_hops::FABRIC_HOPS_HEADER,
        ];
        for name in stripped {
            assert!(!crate::protocols::extensions::should_forward_request_header(name), "{name}");
            assert!(reserved_header(name).is_some(), "{name}");
        }
        for name in crate::proxy::caller_identity::CallerHeaders::NAMES {
            assert!(reserved_header(name).is_some(), "{name}");
        }
    }

    #[test]
    fn a_format_needs_exactly_one_placeholder_and_no_line_break_or_nul() {
        for format in ["{value}", "Bearer {value}", "token={value};"] {
            assert_eq!(header_format_problem(format), None, "{format}");
        }
        for format in ["", "Bearer", "{value} {value}", "{VALUE}", "{ value }"] {
            assert_eq!(header_format_problem(format), Some(HeaderFormatProblem::PlaceholderCount), "{format}");
        }
        for format in ["Bearer {value}\r", "Bearer {value}\nX-Other: 1", "{value}\0", "\r\n"] {
            assert_eq!(header_format_problem(format), Some(HeaderFormatProblem::ControlCharacter), "{format:?}");
        }
    }

    #[test]
    fn only_an_https_url_with_a_host_is_an_https_target() {
        for endpoint in ["https://api.example.com/v1", "HTTPS://api.example.com", " https://10.0.0.1:8443/ "] {
            assert!(is_https_target(endpoint), "{endpoint}");
        }
        for endpoint in [
            "http://api.example.com",
            "fabric://gateway-1/surface",
            "a2a-proxy://proxy-1",
            "proxy://mcp-1",
            "api.example.com",
            "",
        ] {
            assert!(!is_https_target(endpoint), "{endpoint}");
        }
    }

    #[test]
    fn a_proxy_target_sends_over_https_only_when_its_mcp_proxy_base_url_is_https() {
        let proxies = HttpsMcpProxies::from_base_urls([
            ("secure", "https://rest.example.com/api"),
            ("plain", "http://rest.example.com"),
        ]);
        assert!(proxies.sends_over_https("proxy://secure"));
        assert!(proxies.sends_over_https("https://api.example.com/"));
        for endpoint in ["proxy://plain", "proxy://missing", "proxy://", "http://api.example.com", "a2a-proxy://secure"]
        {
            assert!(!proxies.sends_over_https(endpoint), "{endpoint}");
        }
    }

    fn surface() -> crate::config::agent_surface::AgentSurface {
        serde_json::from_value(serde_json::json!({
            "name": "s",
            "access_point": {"listen_address": "0.0.0.0:8443", "route": "/s", "protocol": "mcp"},
            "target": {"endpoint": "https://api.example.com"}
        }))
        .unwrap()
    }

    #[test]
    fn a_surface_checks_callers_with_a_caller_authentication_method_or_a_resource_access_token() {
        assert!(!surface().authenticates_callers());
        let mut empty = surface();
        empty
            .access_point
            .caller_authentication = Some(crate::config::agent_surface::CallerAuthentication {
            methods: vec![],
            protected_resource: None,
            on_failure: Default::default(),
        });
        assert!(!empty.authenticates_callers());

        let mut api_key = surface();
        api_key
            .access_point
            .caller_authentication = Some(
            serde_json::from_value(serde_json::json!({"methods": [{
                "type": "api_key", "secret_id": "caller-key",
                "extraction": {"source": "http_header", "field": "X-Api-Key"}
            }]}))
            .unwrap(),
        );
        assert!(api_key.authenticates_callers());

        let mut two_methods = surface();
        two_methods
            .access_point
            .caller_authentication = Some(
            serde_json::from_value(serde_json::json!({"methods": [
                {"type": "jwt_bearer", "jwt_verification_strategy_id": "strategy", "audiences": []},
                {"type": "api_key", "secret_id": "caller-key",
                 "extraction": {"source": "http_header", "field": "X-Api-Key"}}
            ]}))
            .unwrap(),
        );
        assert!(two_methods.authenticates_callers());

        let mut resource = surface();
        resource.mcp_http = Some(
            serde_json::from_value(serde_json::json!({"authorization": {"resource": "https://gateway.example.com/s"}}))
                .unwrap(),
        );
        assert!(resource.authenticates_callers());
    }
}
