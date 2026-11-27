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
/// no path, query or trailing slash, and one trailing dot dropped from a
/// domain host. `None` for any other scheme.
pub fn normalise_origin(url: &Url) -> Option<String> {
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let mut url = url.clone();
    if let Some(url::Host::Domain(host)) = url.host()
        && let Some(stripped) = host
            .strip_suffix('.')
            .filter(|stripped| !stripped.is_empty())
            .map(str::to_string)
    {
        url.set_host(Some(&stripped))
            .ok()?;
    }
    Some(
        url.origin()
            .ascii_serialization(),
    )
}

/// Why a presentation's `domain` is refused at a verify site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VpDomainRefusal {
    #[error("the presentation names no receiver")]
    Missing,
    #[error("the presentation names a label, which is not a receiver")]
    Label,
    #[error("the presentation's domain is not a DID or an http(s) origin")]
    Unparseable,
    #[error("the presentation names another receiver")]
    Wrong,
}

/// The receivers a verify site accepts in a presentation's `domain`, built
/// from configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedReceivers {
    /// The `domain` is not read. Used only for the agent card presentation,
    /// which is public and names no receiver, and for the Transit Point's
    /// inbound MCP presentation.
    Unchecked,
    /// One of these must be named. None configured refuses every presentation.
    AnyOf(Vec<VpDomain>),
}

impl ExpectedReceivers {
    /// The origins of `urls`, an Access Point's inbound `external_urls`; a URL
    /// that is not http(s) adds none.
    pub fn origins<S: AsRef<str>>(urls: impl IntoIterator<Item = S>) -> Self {
        Self::AnyOf(
            urls.into_iter()
                .filter_map(|url| {
                    Url::parse(url.as_ref())
                        .ok()
                        .as_ref()
                        .and_then(VpDomain::origin)
                })
                .collect(),
        )
    }

    /// The DIDs in `dids`; a value that is not a DID adds none.
    pub fn dids<S: AsRef<str>>(dids: impl IntoIterator<Item = S>) -> Self {
        Self::AnyOf(
            dids.into_iter()
                .filter_map(|did| VpDomain::did(did.as_ref()))
                .collect(),
        )
    }

    /// Checks a presentation proof's `domain`, a string or an array of them.
    /// A label anywhere in it is refused, and an array is accepted when one of
    /// its values is an expected receiver.
    pub fn check(
        &self,
        domain: Option<&serde_json::Value>,
    ) -> Result<(), VpDomainRefusal> {
        let Self::AnyOf(expected) = self else {
            return Ok(());
        };
        let values: Vec<&str> = match domain {
            None => return Err(VpDomainRefusal::Missing),
            Some(serde_json::Value::String(value)) => vec![value.as_str()],
            Some(serde_json::Value::Array(values)) if values.is_empty() => return Err(VpDomainRefusal::Missing),
            Some(serde_json::Value::Array(values)) => values
                .iter()
                .map(serde_json::Value::as_str)
                .collect::<Option<_>>()
                .ok_or(VpDomainRefusal::Unparseable)?,
            Some(_) => return Err(VpDomainRefusal::Unparseable),
        };
        if values
            .iter()
            .any(|value| value.starts_with(VP_DOMAIN_LABEL_PREFIX))
        {
            return Err(VpDomainRefusal::Label);
        }
        let named = values
            .iter()
            .map(|value| receiver_named_by(value))
            .collect::<Option<Vec<_>>>()
            .ok_or(VpDomainRefusal::Unparseable)?;
        if named
            .iter()
            .any(|receiver| expected.contains(receiver))
        {
            Ok(())
        } else {
            Err(VpDomainRefusal::Wrong)
        }
    }
}

/// The receiver a `domain` value names: a DID, or the normalised origin of an
/// http(s) URL.
fn receiver_named_by(value: &str) -> Option<VpDomain> {
    if value.starts_with("did:") {
        return VpDomain::did(value);
    }
    VpDomain::origin(&Url::parse(value).ok()?)
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
            ("https://gateway.example./a2a", Some("https://gateway.example")),
            ("https://gateway.example.:8443", Some("https://gateway.example:8443")),
            ("https://gateway.example../", Some("https://gateway.example.")),
            ("http://127.0.0.1./", Some("http://127.0.0.1")),
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
    fn a_domain_is_accepted_only_when_it_names_an_expected_receiver() {
        use serde_json::json;
        let receivers = ExpectedReceivers::AnyOf(vec![
            VpDomain::did("did:peer:2.ours").unwrap(),
            VpDomain::origin(&Url::parse("https://gateway.example").unwrap()).unwrap(),
        ]);
        let label = "urn:agent-gateway:label:answer";
        for (domain, outcome) in [
            (None, Err(VpDomainRefusal::Missing)),
            (Some(json!([])), Err(VpDomainRefusal::Missing)),
            (Some(json!("did:peer:2.ours")), Ok(())),
            (Some(json!("did:peer:2.ours#key-1")), Ok(())),
            (Some(json!("HTTPS://Gateway.Example:443/a2a")), Ok(())),
            (Some(json!("https://gateway.example.")), Ok(())),
            (Some(json!("did:peer:2.theirs")), Err(VpDomainRefusal::Wrong)),
            (Some(json!("https://other.example")), Err(VpDomainRefusal::Wrong)),
            (Some(json!("https://gateway.example:8443")), Err(VpDomainRefusal::Wrong)),
            (Some(json!(label)), Err(VpDomainRefusal::Label)),
            (Some(json!(["https://other.example", "did:peer:2.ours"])), Ok(())),
            (Some(json!(["https://other.example", "did:peer:2.theirs"])), Err(VpDomainRefusal::Wrong)),
            (Some(json!(["did:peer:2.ours", label])), Err(VpDomainRefusal::Label)),
            (Some(json!(["did:peer:2.ours", "not a receiver"])), Err(VpDomainRefusal::Unparseable)),
            (Some(json!(["did:peer:2.ours", 7])), Err(VpDomainRefusal::Unparseable)),
            (Some(json!("")), Err(VpDomainRefusal::Unparseable)),
            (Some(json!("gateway.example")), Err(VpDomainRefusal::Unparseable)),
            (Some(json!("ws://gateway.example")), Err(VpDomainRefusal::Unparseable)),
            (Some(json!(7)), Err(VpDomainRefusal::Unparseable)),
            (Some(json!({"id": "did:peer:2.ours"})), Err(VpDomainRefusal::Unparseable)),
        ] {
            assert_eq!(receivers.check(domain.as_ref()), outcome, "{domain:?}");
        }
    }

    #[test]
    fn no_configured_receiver_refuses_every_domain_and_an_unchecked_site_reads_none() {
        let none = ExpectedReceivers::origins(Vec::<String>::new());
        assert_eq!(none.check(Some(&serde_json::json!("https://gateway.example"))), Err(VpDomainRefusal::Wrong));
        assert_eq!(none.check(None), Err(VpDomainRefusal::Missing));
        for domain in [None, Some(serde_json::json!("urn:agent-gateway:label:answer"))] {
            assert_eq!(ExpectedReceivers::Unchecked.check(domain.as_ref()), Ok(()), "{domain:?}");
        }
    }

    #[test]
    fn receivers_are_built_from_origins_and_dids_skipping_values_that_name_none() {
        assert_eq!(
            ExpectedReceivers::origins([
                "HTTPS://Gateway.Example:443/",
                "not a url",
                "ws://x.example",
                "http://localhost:8080/a"
            ]),
            ExpectedReceivers::AnyOf(vec![
                VpDomain("https://gateway.example".into()),
                VpDomain("http://localhost:8080".into())
            ])
        );
        assert_eq!(
            ExpectedReceivers::dids(["did:web:gw.example#key-1", "gw.example", "did:webvh:z6:gw.example"]),
            ExpectedReceivers::AnyOf(vec![
                VpDomain("did:web:gw.example".into()),
                VpDomain("did:webvh:z6:gw.example".into())
            ])
        );
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
