//! The receiver an agent presentation names in its proof's `domain`.

use url::Url;

/// Every label starts with this prefix. A label names no receiver, so a
/// presentation whose `domain` starts with it is never accepted as one sent
/// to a receiver.
pub const VP_DOMAIN_LABEL_PREFIX: &str = "urn:agent-gateway:label:";

/// What a presentation that is sent to no verifying receiver was signed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpLabel {
    /// An answer to a caller at an Access Point.
    Answer,
    /// A record kept in the audit log only.
    Audit,
    /// A request handed to one of this gateway's own MCP Proxies.
    Proxy,
}

impl VpLabel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Answer => "answer",
            Self::Audit => "audit",
            Self::Proxy => "proxy",
        }
    }
}

/// The `domain` of a presentation's proof: a DID, an origin or a label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpDomain(String);

impl VpDomain {
    /// A receiver known by its DID, without any `#fragment`; `None` unless it
    /// is a `did:<method>:<id>`.
    pub fn did(did: &str) -> Option<Self> {
        let base = did
            .split_once('#')
            .map_or(did, |(base, _)| base);
        base.strip_prefix("did:")
            .and_then(|rest| rest.split_once(':'))
            .is_some_and(|(method, id)| !method.is_empty() && !id.is_empty())
            .then(|| Self(base.to_string()))
    }

    /// A receiver known by the origin of `url`; `None` unless it is http(s).
    pub fn origin(url: &Url) -> Option<Self> {
        normalise_origin(url).map(Self)
    }

    pub fn label(label: VpLabel) -> Self {
        Self(format!("{VP_DOMAIN_LABEL_PREFIX}{}", label.as_str()))
    }

    /// The receiver of a request sent to `endpoint`: the origin of an http(s)
    /// URL, or the proxy label for one of this gateway's MCP Proxies
    /// (`proxy://`). `None` for anything else, which names no receiver.
    pub fn for_endpoint(endpoint: &str) -> Option<Self> {
        if endpoint.starts_with("proxy://") {
            return Some(Self::label(VpLabel::Proxy));
        }
        Self::origin(&Url::parse(endpoint).ok()?)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The origin of an http(s) URL: lowercase scheme and host, no default port,
/// no path, query or trailing slash. `None` for any other scheme.
pub fn normalise_origin(url: &Url) -> Option<String> {
    matches!(url.scheme(), "http" | "https").then(|| {
        url.origin()
            .ascii_serialization()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_origin_keeps_scheme_host_and_a_port_that_is_not_the_default() {
        for (url, origin) in [
            ("https://gateway.example", Some("https://gateway.example")),
            ("HTTPS://Gateway.EXAMPLE/", Some("https://gateway.example")),
            ("https://gateway.example:443/a2a", Some("https://gateway.example")),
            ("http://gateway.example:80/", Some("http://gateway.example")),
            ("http://gateway.example:443", Some("http://gateway.example:443")),
            ("https://gateway.example:8443/surfaces/x?y=1#z", Some("https://gateway.example:8443")),
            ("http://user:secret@gateway.example:8080/p", Some("http://gateway.example:8080")),
            ("http://127.0.0.1:8080/", Some("http://127.0.0.1:8080")),
            ("http://localhost:8080", Some("http://localhost:8080")),
            ("http://[::1]:8080/mcp", Some("http://[::1]:8080")),
            ("https://[2001:DB8::1]:443/", Some("https://[2001:db8::1]")),
            ("https://bücher.example/", Some("https://xn--bcher-kva.example")),
            ("https://gateway.example./a2a", Some("https://gateway.example.")),
            ("ws://gateway.example/socket", None),
            ("wss://gateway.example", None),
            ("fabric://gw-1/surface", None),
            ("proxy://mcp-proxy-1", None),
            ("a2a-proxy://a2a-proxy-1", None),
            ("did:web:gateway.example", None),
        ] {
            let parsed = Url::parse(url).unwrap();
            assert_eq!(normalise_origin(&parsed).as_deref(), origin, "{url}");
        }
    }

    #[test]
    fn a_did_receiver_is_the_did_without_its_fragment() {
        for (did, domain) in [
            ("did:peer:2.Vz6Mk", Some("did:peer:2.Vz6Mk")),
            ("did:web:gw.example#key-1", Some("did:web:gw.example")),
            ("", None),
            ("#key-1", None),
            ("did:", None),
            ("did:#key-1", None),
            ("did:web:", None),
            ("did::id", None),
            ("gw.example", None),
            ("https://gw.example", None),
        ] {
            assert_eq!(
                VpDomain::did(did)
                    .as_ref()
                    .map(VpDomain::as_str),
                domain,
                "{did:?}"
            );
        }
    }

    #[test]
    fn an_origin_receiver_is_the_normalised_origin_of_an_http_url_only() {
        let url = Url::parse("HTTPS://Partner.Example:443/a2a?x=1").unwrap();
        assert_eq!(
            VpDomain::origin(&url)
                .unwrap()
                .as_str(),
            "https://partner.example"
        );
        assert_eq!(VpDomain::origin(&Url::parse("proxy://mcp-1").unwrap()), None);
    }

    #[test]
    fn every_label_is_under_the_reserved_prefix() {
        for (label, domain) in [
            (VpLabel::Answer, "urn:agent-gateway:label:answer"),
            (VpLabel::Audit, "urn:agent-gateway:label:audit"),
            (VpLabel::Proxy, "urn:agent-gateway:label:proxy"),
        ] {
            let value = VpDomain::label(label);
            assert_eq!(value.as_str(), domain);
            assert!(
                value
                    .as_str()
                    .starts_with(VP_DOMAIN_LABEL_PREFIX)
            );
        }
    }

    #[test]
    fn the_receiver_of_an_endpoint_is_its_origin_or_the_proxy_label() {
        for (endpoint, domain) in [
            ("https://Agent.Example:443/a2a/", Some("https://agent.example")),
            ("http://127.0.0.1:9000/mcp", Some("http://127.0.0.1:9000")),
            ("proxy://mcp-proxy-1", Some("urn:agent-gateway:label:proxy")),
            ("fabric://gw-1/surface", None),
            ("a2a-proxy://a2a-1", None),
            ("ws://agent.example", None),
            ("not a url", None),
        ] {
            assert_eq!(
                VpDomain::for_endpoint(endpoint)
                    .as_ref()
                    .map(VpDomain::as_str),
                domain,
                "{endpoint}"
            );
        }
    }
}
