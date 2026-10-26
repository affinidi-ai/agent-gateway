use serde_json::Value;
use url::Url;

use super::fetch::{get_bounded, parse_fetch_url};
use super::{AuthzServerMetadata, DiscoveryError, DiscoveryFailure, DiscoveryOptions, EgressPosture};
use crate::url_validation::{reject_cloud_metadata_url, validate_webhook_url};

const MAX_ENDPOINT_URL_CHARS: usize = 2048;

/// The RFC 8414 metadata URL, then the OpenID Connect configuration URL, for `issuer`.
///
/// RFC 8414 inserts `/.well-known/oauth-authorization-server` between the host and the
/// issuer path, after removing a terminating `/`; OpenID Connect appends
/// `/.well-known/openid-configuration` to the issuer path, also without its terminating `/`.
///
/// Fails with `invalid_url` unless `issuer` is an absolute http or https URL with a
/// host, no credentials, no query and no fragment. The scheme rule of a posture is
/// applied when the URLs are fetched. Performs no I/O.
pub fn metadata_urls(issuer: &str) -> Result<[String; 2], DiscoveryError> {
    let url = parse_issuer(issuer, EgressPosture::CloudMetadataOnly)?;
    let origin = url
        .origin()
        .ascii_serialization();
    let path = url
        .path()
        .trim_end_matches('/');
    Ok([
        format!("{origin}/.well-known/oauth-authorization-server{path}"),
        format!("{origin}{path}/.well-known/openid-configuration"),
    ])
}

fn parse_issuer(
    issuer: &str,
    posture: EgressPosture,
) -> Result<Url, DiscoveryError> {
    let url = parse_fetch_url(issuer, posture)?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(DiscoveryError::new(DiscoveryFailure::InvalidUrl, "an issuer has no query or fragment"));
    }
    Ok(url)
}

/// Discover the authorization server metadata of `issuer` under `posture`.
///
/// `issuer` must be an absolute URL with a host and no credentials, query or fragment;
/// under [`EgressPosture::Strict`] its scheme must be `https`, and under
/// [`EgressPosture::CloudMetadataOnly`] `http` or `https`. Any other issuer fails with
/// `invalid_url` before the host is resolved or a request is made.
///
/// The RFC 8414 document is fetched first and the OpenID Connect document second, each
/// with [`get_bounded`]: the host is vetted for `posture` and the connection pinned to
/// the vetted addresses, redirects are refused, only a 2xx response is accepted, and the
/// body is capped at `options.max_bytes`, and resolving the host and each request are
/// each limited to `options.timeout`. Each document is validated with [`parse_metadata`].
/// With two fetches, discovery can take up to four times `options.timeout` in all.
///
/// The first acceptable document wins. An `invalid_url`, `blocked` or `unreachable`
/// failure ends discovery at once, since the second URL names the same host; otherwise
/// the more specific failure of the two attempts is returned, from least to most specific:
/// `http_status`, `too_large`, `invalid_document`, `issuer_mismatch`.
pub async fn discover(
    issuer: &str,
    posture: EgressPosture,
    options: DiscoveryOptions,
) -> Result<AuthzServerMetadata, DiscoveryError> {
    let mut worst: Option<DiscoveryError> = None;
    for metadata_url in metadata_urls(issuer)? {
        let attempt = get_bounded(&metadata_url, posture, options)
            .await
            .and_then(|body| parse_metadata(&body, issuer, &metadata_url, posture));
        match attempt {
            Ok(metadata) => return Ok(metadata),
            Err(error)
                if matches!(
                    error.failure(),
                    DiscoveryFailure::InvalidUrl | DiscoveryFailure::Blocked | DiscoveryFailure::Unreachable
                ) =>
            {
                return Err(error);
            }
            Err(error) => {
                worst = Some(match worst {
                    Some(previous) if previous.failure() >= error.failure() => previous,
                    _ => error,
                });
            }
        }
    }
    Err(worst.unwrap_or_else(|| DiscoveryError::new(DiscoveryFailure::HttpStatus, "no metadata document")))
}

/// Validate a metadata document read from `metadata_url` for `issuer`. Performs no I/O.
///
/// `issuer` must be acceptable to [`discover`] under `posture` (`invalid_url` otherwise).
/// The body must be a JSON object whose `issuer` member equals `issuer` byte for byte,
/// trailing slash included (`issuer_mismatch` otherwise). Its `token_endpoint` and
/// `jwks_uri` members must be strings holding absolute http or https URLs of at most
/// 2048 characters, with a host, without whitespace, control characters, credentials or
/// a fragment, and not naming a cloud-metadata host. They must not use a weaker scheme
/// than `issuer`: an `https` issuer requires `https` endpoints under every posture, and
/// an `http` issuer, which only [`EgressPosture::CloudMetadataOnly`] accepts, allows
/// `http` or `https` endpoints. Under [`EgressPosture::Strict`] they must use `https` and
/// must also not name a literal loopback, unspecified, RFC 1918, link-local or
/// unique-local address, nor the name `localhost` or a `.localhost` subdomain. Any other
/// problem fails with `invalid_document`.
///
/// A host name that only resolves to such an address cannot be detected without DNS, so
/// the caller must fetch these URLs with [`get_bounded`], or another pinned client, under
/// the same posture, which blocks such a name at connect time.
pub fn parse_metadata(
    body: &[u8],
    issuer: &str,
    metadata_url: &str,
    posture: EgressPosture,
) -> Result<AuthzServerMetadata, DiscoveryError> {
    let requested = parse_issuer(issuer, posture)?;
    let invalid =
        |detail: &str| DiscoveryError::new(DiscoveryFailure::InvalidDocument, format!("{metadata_url}: {detail}"));
    let document: Value = serde_json::from_slice(body).map_err(|_| invalid("not JSON"))?;
    let document = document
        .as_object()
        .ok_or_else(|| invalid("not a JSON object"))?;
    let discovered = document
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("no issuer"))?;
    if discovered != issuer {
        return Err(DiscoveryError::new(
            DiscoveryFailure::IssuerMismatch,
            format!("{metadata_url}: issuer {discovered:?} is not {issuer:?}"),
        ));
    }
    let endpoint = |name: &str| -> Result<String, DiscoveryError> {
        let value = document
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(&format!("no {name}")))?;
        endpoint_url(value, &requested, posture).map_err(|reason| invalid(&format!("{name} {reason}")))
    };
    Ok(AuthzServerMetadata {
        issuer: issuer.to_string(),
        metadata_url: metadata_url.to_string(),
        token_endpoint: endpoint("token_endpoint")?,
        jwks_uri: endpoint("jwks_uri")?,
    })
}

fn endpoint_url(
    value: &str,
    issuer: &Url,
    posture: EgressPosture,
) -> Result<String, &'static str> {
    if value.chars().count() > MAX_ENDPOINT_URL_CHARS {
        return Err("is too long");
    }
    if value
        .chars()
        .any(|c| c.is_ascii_whitespace() || c.is_control())
    {
        return Err("contains whitespace or a control character");
    }
    let url = parse_fetch_url(value, posture)
        .map_err(|_| "is not an absolute URL without credentials with a scheme the posture accepts")?;
    if issuer.scheme() == "https" && url.scheme() != "https" {
        return Err("uses http while the issuer uses https");
    }
    if url.fragment().is_some() {
        return Err("has a fragment");
    }
    if reject_cloud_metadata_url(value).is_err() {
        return Err("names a cloud-metadata host");
    }
    if posture == EgressPosture::Strict && validate_webhook_url(value).is_err() {
        return Err("names a host the strict egress posture blocks");
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::authz_metadata::test_server::{Reply, TestServer};

    const RFC8414: &str = "/.well-known/oauth-authorization-server";
    const OIDC: &str = "/.well-known/openid-configuration";
    const ISSUER: &str = "https://as.example.com";
    const METADATA_URL: &str = "https://as.example.com/.well-known/oauth-authorization-server";
    const OPERATOR: EgressPosture = EgressPosture::CloudMetadataOnly;
    const STRICT: EgressPosture = EgressPosture::Strict;

    fn document(issuer: &str) -> Value {
        json!({
            "issuer": issuer,
            "token_endpoint": format!("{}/token", issuer.trim_end_matches('/')),
            "jwks_uri": format!("{}/jwks.json", issuer.trim_end_matches('/')),
        })
    }

    fn expected(
        issuer: &str,
        metadata_url: String,
    ) -> AuthzServerMetadata {
        AuthzServerMetadata {
            issuer: issuer.to_string(),
            metadata_url,
            token_endpoint: format!("{}/token", issuer.trim_end_matches('/')),
            jwks_uri: format!("{}/jwks.json", issuer.trim_end_matches('/')),
        }
    }

    fn parse(
        doc: &Value,
        posture: EgressPosture,
    ) -> Result<AuthzServerMetadata, DiscoveryError> {
        parse_metadata(doc.to_string().as_bytes(), ISSUER, METADATA_URL, posture)
    }

    fn with_endpoint(
        field: &str,
        value: Value,
    ) -> Value {
        let mut doc = document(ISSUER);
        doc[field] = value;
        doc
    }

    fn parse_for(
        issuer: &str,
        token_endpoint: &str,
        jwks_uri: &str,
        posture: EgressPosture,
    ) -> Result<AuthzServerMetadata, DiscoveryError> {
        let doc = json!({ "issuer": issuer, "token_endpoint": token_endpoint, "jwks_uri": jwks_uri });
        parse_metadata(doc.to_string().as_bytes(), issuer, METADATA_URL, posture)
    }

    fn endpoint_of(
        field: &str,
        value: &str,
        posture: EgressPosture,
    ) -> Result<String, DiscoveryError> {
        parse(&with_endpoint(field, json!(value)), posture).map(|metadata| {
            if field == "token_endpoint" {
                metadata.token_endpoint
            } else {
                metadata.jwks_uri
            }
        })
    }

    async fn discovered(
        issuer: &str,
        options: DiscoveryOptions,
    ) -> Result<AuthzServerMetadata, DiscoveryError> {
        discover(issuer, OPERATOR, options).await
    }

    #[test]
    fn metadata_urls_follow_rfc_8414_and_openid_connect() {
        let origin = [
            "https://as.example.com/.well-known/oauth-authorization-server",
            "https://as.example.com/.well-known/openid-configuration",
        ];
        assert_eq!(metadata_urls("https://as.example.com").unwrap(), origin);
        assert_eq!(metadata_urls("https://as.example.com/").unwrap(), origin);
        let path = [
            "https://login.example.com/.well-known/oauth-authorization-server/tenant/v2.0",
            "https://login.example.com/tenant/v2.0/.well-known/openid-configuration",
        ];
        assert_eq!(metadata_urls("https://login.example.com/tenant/v2.0").unwrap(), path);
        assert_eq!(metadata_urls("https://login.example.com/tenant/v2.0/").unwrap(), path);
        assert_eq!(
            metadata_urls("http://127.0.0.1:4444").unwrap(),
            [
                "http://127.0.0.1:4444/.well-known/oauth-authorization-server",
                "http://127.0.0.1:4444/.well-known/openid-configuration"
            ]
        );
    }

    #[test]
    fn an_issuer_with_a_query_fragment_or_credentials_or_no_url_is_refused() {
        for issuer in [
            "https://as.example.com/?tenant=a",
            "https://as.example.com/#x",
            "https://u:p@as.example.com/",
            "https://user@as.example.com",
            "https://:pw@as.example.com",
            "as.example.com",
            "did:web:as.example.com",
            "ftp://as.example.com/",
            "",
        ] {
            let error = metadata_urls(issuer).unwrap_err();
            assert_eq!(error.failure(), DiscoveryFailure::InvalidUrl, "{issuer}");
            assert_eq!(error.code(), "invalid_url", "{issuer}");
        }
    }

    #[test]
    fn metadata_urls_accept_an_http_or_https_issuer_of_any_case() {
        assert_eq!(
            metadata_urls("HTTPS://as.example.com").unwrap(),
            [
                "https://as.example.com/.well-known/oauth-authorization-server",
                "https://as.example.com/.well-known/openid-configuration"
            ]
        );
        assert_eq!(
            metadata_urls("HTTP://as.example.com").unwrap(),
            [
                "http://as.example.com/.well-known/oauth-authorization-server",
                "http://as.example.com/.well-known/openid-configuration"
            ]
        );
    }

    #[test]
    fn an_issuer_with_only_a_user_name_or_only_a_password_is_refused() {
        for issuer in ["https://user@as.example.com", "https://:pw@as.example.com"] {
            assert_eq!(
                metadata_urls(issuer)
                    .unwrap_err()
                    .code(),
                "invalid_url",
                "{issuer}"
            );
        }
    }

    #[test]
    fn a_complete_document_parses_into_the_pinned_fields() {
        let doc = json!({
            "issuer": ISSUER,
            "token_endpoint": "https://as.example.com/token",
            "jwks_uri": "https://keys.example.net/jwks.json",
            "response_types_supported": ["code"]
        });
        assert_eq!(
            parse(&doc, STRICT).unwrap(),
            AuthzServerMetadata {
                issuer: ISSUER.to_string(),
                metadata_url: METADATA_URL.to_string(),
                token_endpoint: "https://as.example.com/token".to_string(),
                jwks_uri: "https://keys.example.net/jwks.json".to_string(),
            }
        );
    }

    #[test]
    fn a_body_that_is_not_a_json_object_is_an_invalid_document() {
        for body in [&b"<html>"[..], b"[]", b"\"text\"", b"42", b"null", b""] {
            let error = parse_metadata(body, ISSUER, METADATA_URL, OPERATOR).unwrap_err();
            assert_eq!(error.code(), "invalid_document", "{body:?}");
        }
    }

    #[test]
    fn a_missing_or_non_string_issuer_is_an_invalid_document() {
        let mut doc = document(ISSUER);
        doc["issuer"] = json!(42);
        assert_eq!(
            parse(&doc, OPERATOR)
                .unwrap_err()
                .failure(),
            DiscoveryFailure::InvalidDocument
        );
        doc.as_object_mut()
            .unwrap()
            .remove("issuer");
        assert_eq!(
            parse(&doc, OPERATOR)
                .unwrap_err()
                .failure(),
            DiscoveryFailure::InvalidDocument
        );
    }

    #[test]
    fn the_issuer_must_match_byte_for_byte() {
        for (requested, advertised) in [
            ("https://as.example.com", "https://as.example.com/"),
            ("https://as.example.com/", "https://as.example.com"),
            ("https://as.example.com", "https://AS.example.com"),
            ("https://as.example.com", "https://other.example.com"),
        ] {
            let error = parse_metadata(
                document(advertised)
                    .to_string()
                    .as_bytes(),
                requested,
                METADATA_URL,
                OPERATOR,
            )
            .unwrap_err();
            assert_eq!(error.failure(), DiscoveryFailure::IssuerMismatch, "{requested} vs {advertised}");
            assert_eq!(error.code(), "issuer_mismatch");
        }
    }

    #[test]
    fn missing_or_non_string_endpoints_are_invalid() {
        for field in ["token_endpoint", "jwks_uri"] {
            for value in [Value::Null, json!(42), json!(["https://as.example.com/x"]), json!({})] {
                let error = parse(&with_endpoint(field, value.clone()), OPERATOR).unwrap_err();
                assert_eq!(error.failure(), DiscoveryFailure::InvalidDocument, "{field} = {value}");
            }
            let mut doc = document(ISSUER);
            doc.as_object_mut()
                .unwrap()
                .remove(field);
            assert_eq!(
                parse(&doc, OPERATOR)
                    .unwrap_err()
                    .failure(),
                DiscoveryFailure::InvalidDocument,
                "{field}"
            );
        }
    }

    #[test]
    fn unacceptable_endpoint_urls_are_invalid_under_both_postures() {
        for value in [
            "https://user:pw@as.example.com/token",
            "https://as.example.com/token#frag",
            " https://as.example.com/token",
            "https://as.example.com/token ",
            "https://as.example.com/jw\nks.json",
            "https://as.example.com/to\tken",
            "https://as.example.com/token\u{0}",
            "/token",
            "token",
            "file:///etc/passwd",
            "ftp://as.example.com/token",
            "javascript:alert(1)",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::ffff:169.254.169.254]/jwks",
            "https://[fd00:ec2::254]/latest/meta-data/",
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://METADATA.GOOGLE.INTERNAL./computeMetadata/v1/",
        ] {
            for field in ["token_endpoint", "jwks_uri"] {
                for posture in [OPERATOR, STRICT] {
                    let error = parse(&with_endpoint(field, json!(value)), posture).unwrap_err();
                    assert_eq!(
                        error.failure(),
                        DiscoveryFailure::InvalidDocument,
                        "{field} = {value} under {posture:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn cloud_metadata_endpoints_are_invalid_for_an_http_issuer() {
        let issuer = "http://127.0.0.1:4444";
        for value in [
            "http://169.254.169.254/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/jwks",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://METADATA.GOOGLE.INTERNAL./computeMetadata/v1/",
        ] {
            for (token_endpoint, jwks_uri) in
                [(value, "http://127.0.0.1:4444/jwks.json"), ("http://127.0.0.1:4444/token", value)]
            {
                let error = parse_for(issuer, token_endpoint, jwks_uri, OPERATOR).unwrap_err();
                assert_eq!(error.code(), "invalid_document", "{token_endpoint} {jwks_uri}");
            }
        }
    }

    #[test]
    fn an_endpoint_may_have_2048_characters_and_not_2049() {
        let prefix = "https://as.example.com/";
        let at_limit = format!("{prefix}{}", "a".repeat(2048 - prefix.len()));
        let over_limit = format!("{prefix}{}", "a".repeat(2048 + 1 - prefix.len()));
        assert_eq!(at_limit.chars().count(), 2048);
        assert_eq!(over_limit.chars().count(), 2048 + 1);
        for field in ["token_endpoint", "jwks_uri"] {
            for posture in [OPERATOR, STRICT] {
                assert_eq!(endpoint_of(field, &at_limit, posture).unwrap(), at_limit, "{field} under {posture:?}");
                assert_eq!(
                    endpoint_of(field, &over_limit, posture)
                        .unwrap_err()
                        .code(),
                    "invalid_document",
                    "{field} under {posture:?}"
                );
            }
        }
    }

    #[test]
    fn an_endpoint_with_only_a_user_name_or_only_a_password_is_invalid() {
        for value in ["https://user@as.example.com/token", "https://:pw@as.example.com/token"] {
            for field in ["token_endpoint", "jwks_uri"] {
                assert_eq!(
                    endpoint_of(field, value, OPERATOR)
                        .unwrap_err()
                        .code(),
                    "invalid_document",
                    "{field} = {value}"
                );
            }
        }
    }

    #[test]
    fn an_https_issuer_requires_https_endpoints_under_both_postures() {
        for value in ["http://as.example.com/token", "HTTP://as.example.com/token", "http://203.0.113.7/jwks.json"] {
            for field in ["token_endpoint", "jwks_uri"] {
                for posture in [OPERATOR, STRICT] {
                    assert_eq!(
                        endpoint_of(field, value, posture)
                            .unwrap_err()
                            .code(),
                        "invalid_document",
                        "{field} = {value} under {posture:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn an_http_issuer_accepts_http_and_https_endpoints_under_the_operator_posture() {
        for issuer in ["http://127.0.0.1:4444", "HTTP://127.0.0.1:4444"] {
            for (token_endpoint, jwks_uri) in [
                ("http://127.0.0.1:4444/token", "http://127.0.0.1:4444/jwks.json"),
                ("https://as.example.com/token", "https://keys.example.net/jwks.json"),
                ("HTTP://127.0.0.1:4444/token", "HTTPS://keys.example.net/jwks.json"),
            ] {
                let metadata = parse_for(issuer, token_endpoint, jwks_uri, OPERATOR).unwrap();
                assert_eq!(metadata.issuer, issuer);
                assert_eq!(metadata.token_endpoint, token_endpoint);
                assert_eq!(metadata.jwks_uri, jwks_uri);
            }
        }
    }

    #[test]
    fn an_http_issuer_is_an_invalid_url_under_the_strict_posture() {
        for issuer in ["http://as.example.com", "HTTP://as.example.com"] {
            let error = parse_for(issuer, "https://as.example.com/token", "https://as.example.com/jwks.json", STRICT)
                .unwrap_err();
            assert_eq!(error.code(), "invalid_url", "{issuer}");
        }
    }

    #[test]
    fn an_upper_case_https_issuer_and_endpoints_are_accepted_under_the_strict_posture() {
        let metadata = parse_for(
            "HTTPS://as.example.com",
            "HTTPS://as.example.com/token",
            "https://203.0.113.7/jwks.json",
            STRICT,
        )
        .unwrap();
        assert_eq!(metadata.issuer, "HTTPS://as.example.com");
        assert_eq!(metadata.token_endpoint, "HTTPS://as.example.com/token");
        assert_eq!(metadata.jwks_uri, "https://203.0.113.7/jwks.json");
        assert_eq!(
            parse_for(
                "HTTPS://as.example.com",
                "HTTP://as.example.com/token",
                "https://as.example.com/jwks.json",
                OPERATOR
            )
            .unwrap_err()
            .code(),
            "invalid_document"
        );
    }

    #[test]
    fn the_strict_posture_rejects_internal_endpoint_hosts_that_the_operator_posture_accepts() {
        for value in [
            "https://127.0.0.1:4444/jwks.json",
            "https://[::1]/jwks.json",
            "https://0.0.0.0/jwks.json",
            "https://[::]/jwks.json",
            "https://2130706433/jwks.json",
            "https://0x0a000001/jwks.json",
            "https://[::ffff:127.0.0.1]/jwks.json",
            "https://10.0.0.5/jwks.json",
            "https://172.16.3.4/jwks.json",
            "https://192.168.1.10/jwks.json",
            "https://169.254.10.20/jwks.json",
            "https://[fe80::1]/jwks.json",
            "https://[fd00::1]/jwks.json",
            "https://[::ffff:10.0.0.5]/jwks.json",
            "https://localhost:8080/jwks.json",
            "https://LOCALHOST./jwks.json",
            "https://auth.localhost/jwks.json",
        ] {
            for field in ["token_endpoint", "jwks_uri"] {
                let error = endpoint_of(field, value, STRICT).unwrap_err();
                assert_eq!(error.failure(), DiscoveryFailure::InvalidDocument, "{field} = {value}");
                assert_eq!(endpoint_of(field, value, OPERATOR).unwrap(), value, "{field}");
            }
        }
    }

    #[test]
    fn the_strict_posture_accepts_public_https_endpoint_hosts_only() {
        assert_eq!(
            endpoint_of("jwks_uri", "https://203.0.113.7/jwks.json", STRICT).unwrap(),
            "https://203.0.113.7/jwks.json"
        );
        assert_eq!(
            endpoint_of("jwks_uri", "http://203.0.113.7/jwks.json", STRICT)
                .unwrap_err()
                .failure(),
            DiscoveryFailure::InvalidDocument
        );
    }

    #[tokio::test]
    async fn an_origin_issuer_is_discovered_from_rfc_8414_metadata() {
        let server = TestServer::start().await;
        let issuer = server.base().to_string();
        server.reply(RFC8414, Reply::json(&document(&issuer).to_string()));
        let metadata = discovered(&issuer, DiscoveryOptions::default())
            .await
            .unwrap();
        assert_eq!(metadata, expected(&issuer, server.url(RFC8414)));
        assert_eq!(server.requests(), [RFC8414]);
    }

    #[tokio::test]
    async fn a_trailing_slash_issuer_keeps_its_slash() {
        let server = TestServer::start().await;
        let issuer = format!("{}/", server.base());
        server.reply(RFC8414, Reply::json(&document(&issuer).to_string()));
        let metadata = discovered(&issuer, DiscoveryOptions::default())
            .await
            .unwrap();
        assert_eq!(metadata.issuer, issuer);
        assert_eq!(metadata, expected(&issuer, server.url(RFC8414)));
    }

    #[tokio::test]
    async fn a_trailing_slash_difference_is_an_issuer_mismatch() {
        let server = TestServer::start().await;
        let issuer = server.base().to_string();
        let advertised = document(&format!("{issuer}/")).to_string();
        server.reply(RFC8414, Reply::json(&advertised));
        server.reply(OIDC, Reply::json(&advertised));
        let error = discovered(&issuer, DiscoveryOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.code(), "issuer_mismatch");
        assert_eq!(server.requests(), [RFC8414, OIDC]);
    }

    #[tokio::test]
    async fn a_path_issuer_falls_back_to_openid_connect() {
        let server = TestServer::start().await;
        let issuer = server.url("/realms/agents/");
        server.reply("/realms/agents/.well-known/openid-configuration", Reply::json(&document(&issuer).to_string()));
        let metadata = discovered(&issuer, DiscoveryOptions::default())
            .await
            .unwrap();
        assert_eq!(metadata, expected(&issuer, server.url("/realms/agents/.well-known/openid-configuration")));
        assert_eq!(
            server.requests(),
            [
                "/.well-known/oauth-authorization-server/realms/agents",
                "/realms/agents/.well-known/openid-configuration"
            ]
        );
    }

    #[tokio::test]
    async fn a_wrong_issuer_in_the_rfc_8414_document_falls_back_to_openid_connect() {
        let server = TestServer::start().await;
        let issuer = server.base().to_string();
        server.reply(RFC8414, Reply::json(&document("https://other.example.com").to_string()));
        server.reply(OIDC, Reply::json(&document(&issuer).to_string()));
        let metadata = discovered(&issuer, DiscoveryOptions::default())
            .await
            .unwrap();
        assert_eq!(metadata.metadata_url, server.url(OIDC));
        assert_eq!(metadata, expected(&issuer, server.url(OIDC)));
        assert_eq!(server.requests(), [RFC8414, OIDC]);
    }

    #[tokio::test]
    async fn when_both_documents_are_missing_the_status_failure_is_returned() {
        let server = TestServer::start().await;
        let error = discovered(server.base(), DiscoveryOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.failure(), DiscoveryFailure::HttpStatus);
        assert_eq!(server.requests(), [RFC8414, OIDC]);
    }

    #[tokio::test]
    async fn the_most_specific_failure_of_both_attempts_is_returned() {
        let server = TestServer::start().await;
        let issuer = server.base().to_string();
        server.reply(RFC8414, Reply::json(&document("https://other.example.com").to_string()));
        server.reply(OIDC, Reply::status(404));
        assert_eq!(
            discovered(&issuer, DiscoveryOptions::default())
                .await
                .unwrap_err()
                .failure(),
            DiscoveryFailure::IssuerMismatch
        );

        server.reply(RFC8414, Reply::status(500));
        server.reply(OIDC, Reply::json("[]"));
        assert_eq!(
            discovered(&issuer, DiscoveryOptions::default())
                .await
                .unwrap_err()
                .failure(),
            DiscoveryFailure::InvalidDocument
        );
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_too_large() {
        let server = TestServer::start().await;
        let issuer = server.base().to_string();
        let body = document(&issuer).to_string();
        server.reply(RFC8414, Reply::json(&body));
        let options = DiscoveryOptions {
            max_bytes: body.len() - 1,
            ..DiscoveryOptions::default()
        };
        let error = discovered(&issuer, options)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "too_large");
        assert_eq!(server.requests(), [RFC8414, OIDC]);
    }

    #[tokio::test]
    async fn a_redirect_is_refused_and_not_followed() {
        let server = TestServer::start().await;
        let issuer = server.base().to_string();
        server.reply(RFC8414, Reply::redirect(&server.url("/moved")));
        server.reply("/moved", Reply::json(&document(&issuer).to_string()));
        let error = discovered(&issuer, DiscoveryOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.code(), "http_status");
        assert_eq!(server.hits("/moved"), 0);
    }

    #[tokio::test]
    async fn an_unreachable_first_url_ends_discovery_at_once() {
        let server = TestServer::start().await;
        let issuer = server.base().to_string();
        server.reply(RFC8414, Reply::json(&document(&issuer).to_string()).delayed(Duration::from_secs(5)));
        server.reply(OIDC, Reply::json(&document(&issuer).to_string()));
        let options = DiscoveryOptions {
            timeout: Duration::from_millis(200),
            ..DiscoveryOptions::default()
        };
        let error = discovered(&issuer, options)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "unreachable");
        assert_eq!(server.hits(OIDC), 0);
    }

    #[tokio::test]
    async fn a_closed_port_is_unreachable() {
        let error = discovered("http://127.0.0.1:1", DiscoveryOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.failure(), DiscoveryFailure::Unreachable);
    }

    #[tokio::test]
    async fn the_strict_posture_never_reaches_a_loopback_issuer() {
        let server = TestServer::start().await;
        let issuer = server.https_url("");
        server.reply(RFC8414, Reply::json(&document(&issuer).to_string()));
        let error = discover(&issuer, STRICT, DiscoveryOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.failure(), DiscoveryFailure::Blocked);
        assert!(server.requests().is_empty());
    }

    #[tokio::test]
    async fn the_strict_posture_refuses_an_http_issuer_before_any_request() {
        let server = TestServer::start().await;
        let issuer = server.base().to_string();
        server.reply(RFC8414, Reply::json(&document(&issuer).to_string()));
        server.reply(OIDC, Reply::json(&document(&issuer).to_string()));
        let error = discover(&issuer, STRICT, DiscoveryOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.code(), "invalid_url");
        assert!(server.requests().is_empty());
    }

    #[tokio::test]
    async fn the_strict_posture_lets_a_public_https_issuer_through_its_checks() {
        let options = DiscoveryOptions {
            timeout: Duration::from_millis(300),
            ..DiscoveryOptions::default()
        };
        let error = discover("https://203.0.113.7:9", STRICT, options)
            .await
            .unwrap_err();
        assert_eq!(error.failure(), DiscoveryFailure::Unreachable);
    }

    #[tokio::test]
    async fn a_cloud_metadata_issuer_is_blocked_under_both_postures() {
        for (issuer, posture) in [
            ("http://169.254.169.254/latest", OPERATOR),
            ("https://169.254.169.254/latest", OPERATOR),
            ("https://169.254.169.254/latest", STRICT),
        ] {
            let error = discover(issuer, posture, DiscoveryOptions::default())
                .await
                .unwrap_err();
            assert_eq!(error.code(), "blocked", "{issuer} under {posture:?}");
        }
    }

    #[tokio::test]
    async fn an_invalid_issuer_fails_before_any_request() {
        let error = discovered("https://as.example.com/?tenant=a", DiscoveryOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.code(), "invalid_url");
    }
}
