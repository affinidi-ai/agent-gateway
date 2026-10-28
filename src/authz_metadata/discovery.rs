use serde_json::Value;
use url::Url;

use super::fetch::{get_bounded, parse_fetch_url};
use super::{AuthzServerMetadata, DiscoveryError, DiscoveryFailure, DiscoveryOptions, EgressPosture};
use crate::url_validation::{reject_cloud_metadata_url, validate_webhook_url};

const MAX_ENDPOINT_URL_CHARS: usize = 2048;
const MAX_LOGGED_ISSUER_CHARS: usize = 200;
const RFC8414_SUFFIX: &str = "/.well-known/oauth-authorization-server";
const OIDC_SUFFIX: &str = "/.well-known/openid-configuration";

/// The candidate metadata URLs for `issuer`, in the order [`discover`] tries them.
///
/// Let the issuer path be its path without terminating `/` characters. For an issuer
/// without a path (an origin, with or without a trailing `/`) there are two URLs:
/// `{origin}/.well-known/oauth-authorization-server`, then
/// `{origin}/.well-known/openid-configuration`. For an issuer with a path there are three:
/// the RFC 8414 path insertion `{origin}/.well-known/oauth-authorization-server{path}`,
/// the OpenID Connect path insertion `{origin}/.well-known/openid-configuration{path}`,
/// then the OpenID Connect path appending `{origin}{path}/.well-known/openid-configuration`.
///
/// Fails with `invalid_url` unless `issuer` is an absolute http or https URL with a
/// host, no credentials, no query, no fragment, and no whitespace or control character
/// anywhere. The scheme rule of a posture is applied when the URLs are fetched.
/// Performs no I/O.
pub fn metadata_urls(issuer: &str) -> Result<Vec<String>, DiscoveryError> {
    let url = parse_issuer(issuer, EgressPosture::CloudMetadataOnly)?;
    let origin = url
        .origin()
        .ascii_serialization();
    let path = url
        .path()
        .trim_end_matches('/');
    if path.is_empty() {
        return Ok(vec![format!("{origin}{RFC8414_SUFFIX}"), format!("{origin}{OIDC_SUFFIX}")]);
    }
    Ok(vec![
        format!("{origin}{RFC8414_SUFFIX}{path}"),
        format!("{origin}{OIDC_SUFFIX}{path}"),
        format!("{origin}{path}{OIDC_SUFFIX}"),
    ])
}

/// Check `issuer` as [`discover`] does before any request, under `posture`: an absolute
/// URL with a host and no credentials, query, fragment, whitespace or control character,
/// `https` only under [`EgressPosture::Strict`] (`invalid_url` otherwise). Resolves no
/// host and blocks no address. Performs no I/O.
pub fn validate_issuer(
    issuer: &str,
    posture: EgressPosture,
) -> Result<(), DiscoveryError> {
    parse_issuer(issuer, posture).map(|_| ())
}

/// Unicode whitespace too: the URL parser would percent-encode a no-break space
/// or a line separator in a path into a URL the operator never meant.
fn has_whitespace_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
}

fn parse_issuer(
    issuer: &str,
    posture: EgressPosture,
) -> Result<Url, DiscoveryError> {
    if has_whitespace_or_control(issuer) {
        return Err(DiscoveryError::new(
            DiscoveryFailure::InvalidUrl,
            "an issuer has no whitespace or control character",
        ));
    }
    let url = parse_fetch_url(issuer, posture)?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(DiscoveryError::new(DiscoveryFailure::InvalidUrl, "an issuer has no query or fragment"));
    }
    Ok(url)
}

/// Discover the authorization server metadata of `issuer` under `posture`.
///
/// `issuer` must be an absolute URL with a host and no credentials, query, fragment,
/// whitespace or control character; under [`EgressPosture::Strict`] its scheme must be
/// `https`, and under [`EgressPosture::CloudMetadataOnly`] `http` or `https`. Any other
/// issuer fails with `invalid_url` before the host is resolved or a request is made.
///
/// The URLs of [`metadata_urls`] are fetched in order, each with [`get_bounded`]: the
/// host is vetted for `posture` and the connection pinned to the vetted addresses,
/// redirects are refused, only a 2xx response is accepted, the body is capped at
/// `options.max_bytes`, and resolving the host and each request are each limited to
/// `options.timeout`. Each document is validated with [`parse_metadata`]. A fetch can
/// take up to twice `options.timeout`, and discovery makes up to three fetches for an
/// issuer with a path and two for an origin issuer, so up to six or four times
/// `options.timeout` in all.
///
/// The first acceptable document wins. An `invalid_url`, `blocked` or `unreachable`
/// failure ends discovery at once, since every URL names the same host; otherwise the
/// most specific failure of all the attempts is returned, from least to most specific:
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
/// trailing slash included (`issuer_mismatch` otherwise, whose detail shows at most the
/// first 200 characters of the escaped discovered issuer). Its `token_endpoint` and
/// `jwks_uri` members are required, `jwks_uri` too although RFC 8414 makes it optional,
/// because the gateway validates JWT access tokens and needs the issuer's keys. They
/// must be strings holding absolute http or https URLs of at most
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
/// the same posture, which blocks such a name at connect time. The JWT Bearer
/// `JwksFetcher` always uses the cloud-metadata-only pinned client, so a `jwks_uri`
/// discovered under [`EgressPosture::Strict`] must not be handed to it: fetch it with
/// [`get_bounded`] under `Strict`.
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
            format!("{metadata_url}: issuer {} is not {issuer:?}", escaped_for_log(discovered)),
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
    if has_whitespace_or_control(value) {
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

fn escaped_for_log(value: &str) -> String {
    let escaped = format!("{value:?}");
    if escaped.chars().count() <= MAX_LOGGED_ISSUER_CHARS {
        return escaped;
    }
    let mut shown: String = escaped
        .chars()
        .take(MAX_LOGGED_ISSUER_CHARS)
        .collect();
    shown.push('…');
    shown
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
    fn an_origin_issuer_has_two_metadata_urls() {
        let origin = [
            "https://as.example.com/.well-known/oauth-authorization-server",
            "https://as.example.com/.well-known/openid-configuration",
        ];
        for issuer in ["https://as.example.com", "https://as.example.com/", "https://as.example.com//"] {
            assert_eq!(metadata_urls(issuer).unwrap(), origin, "{issuer}");
        }
        assert_eq!(
            metadata_urls("http://127.0.0.1:4444").unwrap(),
            [
                "http://127.0.0.1:4444/.well-known/oauth-authorization-server",
                "http://127.0.0.1:4444/.well-known/openid-configuration"
            ]
        );
        assert_eq!(
            metadata_urls("http://127.0.0.1:4444/").unwrap(),
            [
                "http://127.0.0.1:4444/.well-known/oauth-authorization-server",
                "http://127.0.0.1:4444/.well-known/openid-configuration"
            ]
        );
    }

    #[test]
    fn a_path_issuer_has_the_rfc_8414_then_both_openid_connect_urls() {
        let one_segment = [
            "https://as.example.com/.well-known/oauth-authorization-server/realms",
            "https://as.example.com/.well-known/openid-configuration/realms",
            "https://as.example.com/realms/.well-known/openid-configuration",
        ];
        assert_eq!(metadata_urls("https://as.example.com/realms").unwrap(), one_segment);
        assert_eq!(metadata_urls("https://as.example.com/realms/").unwrap(), one_segment);
        let nested = [
            "https://login.example.com/.well-known/oauth-authorization-server/tenant/v2.0",
            "https://login.example.com/.well-known/openid-configuration/tenant/v2.0",
            "https://login.example.com/tenant/v2.0/.well-known/openid-configuration",
        ];
        assert_eq!(metadata_urls("https://login.example.com/tenant/v2.0").unwrap(), nested);
        assert_eq!(metadata_urls("https://login.example.com/tenant/v2.0/").unwrap(), nested);
        assert_eq!(metadata_urls("https://login.example.com/tenant/v2.0//").unwrap(), nested);
        assert_eq!(
            metadata_urls("http://127.0.0.1:4444/realms/agents/").unwrap(),
            [
                "http://127.0.0.1:4444/.well-known/oauth-authorization-server/realms/agents",
                "http://127.0.0.1:4444/.well-known/openid-configuration/realms/agents",
                "http://127.0.0.1:4444/realms/agents/.well-known/openid-configuration"
            ]
        );
    }

    #[test]
    fn an_origin_issuer_never_yields_a_duplicate_url() {
        for issuer in ["https://as.example.com", "https://as.example.com/", "http://127.0.0.1:4444/"] {
            let mut urls = metadata_urls(issuer).unwrap();
            urls.sort();
            urls.dedup();
            assert_eq!(urls.len(), 2, "{issuer}");
        }
    }

    #[test]
    fn an_issuer_with_whitespace_or_a_control_character_is_an_invalid_url() {
        for issuer in [
            "https://as.example.com\n",
            " https://as.example.com",
            "https://as.example.com ",
            "https://as.example.com/te\tnant",
            "https://as.example.com/te\nnant",
            "https://as.example.com/\0",
            "https://as.example.com\r",
            "https://as.example.com/te\u{a0}nant",
            "https://as.example.com/tenant\u{2028}",
            "\u{3000}https://as.example.com",
        ] {
            let error = metadata_urls(issuer).unwrap_err();
            assert_eq!(error.code(), "invalid_url", "{issuer:?}");
            let error = parse_for(issuer, "https://as.example.com/token", "https://as.example.com/jwks.json", OPERATOR)
                .unwrap_err();
            assert_eq!(error.code(), "invalid_url", "{issuer:?}");
        }
        assert_eq!(
            metadata_urls("https://as.example.com/tenant")
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            parse_for(
                "https://as.example.com/tenant",
                "https://as.example.com/token",
                "https://as.example.com/jwks.json",
                OPERATOR
            )
            .unwrap()
            .issuer,
            "https://as.example.com/tenant"
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
    fn validate_issuer_applies_the_issuer_rules_of_a_posture_without_any_request() {
        for issuer in ["https://as.example.com", "https://localhost:4444", "https://as.example.com/tenant/"] {
            assert!(validate_issuer(issuer, EgressPosture::Strict).is_ok(), "{issuer}");
        }
        assert!(validate_issuer("http://127.0.0.1:4444", EgressPosture::CloudMetadataOnly).is_ok());
        for issuer in [
            "http://as.example.com",
            "https://as.example.com/?tenant=a",
            "https://as.example.com/#x",
            "https://u:p@as.example.com/",
            "https://as.example.com/tenant\n",
            "as.example.com",
        ] {
            let error = validate_issuer(issuer, EgressPosture::Strict).unwrap_err();
            assert_eq!(error.failure(), DiscoveryFailure::InvalidUrl, "{issuer:?}");
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
    fn a_long_mismatching_issuer_is_truncated_in_the_detail() {
        let advertised = format!("https://other.example.com/{}", "a".repeat(64 * 1024));
        let error = parse(&document(&advertised), OPERATOR).unwrap_err();
        assert_eq!(error.code(), "issuer_mismatch");
        assert_eq!(error.message(), "The discovered issuer does not match the expected issuer");
        let detail = error.detail();
        assert!(detail.chars().count() <= 600, "{} characters", detail.chars().count());
        let first_50: String = advertised
            .chars()
            .take(50)
            .collect();
        assert!(detail.contains(&first_50), "{detail}");
        assert!(detail.contains('…'), "{detail}");
        assert!(detail.ends_with(&format!(" is not {ISSUER:?}")), "{detail}");
        let shown = format!("{advertised:?}")
            .chars()
            .take(200)
            .collect::<String>();
        assert_eq!(detail, format!("{METADATA_URL}: issuer {shown}… is not {ISSUER:?}"));
    }

    #[test]
    fn a_short_mismatching_issuer_is_shown_in_full_and_escaped() {
        let advertised = "https://other.example.com/\"x\"\n";
        let error = parse(&document(advertised), OPERATOR).unwrap_err();
        assert_eq!(error.code(), "issuer_mismatch");
        assert_eq!(error.message(), "The discovered issuer does not match the expected issuer");
        assert_eq!(
            error.detail(),
            format!(
                "{METADATA_URL}: issuer \"https://other.example.com/\\\"x\\\"\\n\" is not \"https://as.example.com\""
            )
        );
        assert!(!error.detail().contains('…'));
    }

    #[test]
    fn the_escaped_issuer_is_cut_at_200_characters_not_bytes() {
        let at_limit = "é".repeat(198);
        assert_eq!(escaped_for_log(&at_limit), format!("\"{at_limit}\""));
        let over_limit = "é".repeat(199);
        let shown = escaped_for_log(&over_limit);
        assert_eq!(shown, format!("\"{}…", "é".repeat(199)));
        assert_eq!(shown.chars().count(), 201);
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

    const PATH_RFC8414: &str = "/.well-known/oauth-authorization-server/realms/agents";
    const PATH_OIDC_INSERTED: &str = "/.well-known/openid-configuration/realms/agents";
    const PATH_OIDC_APPENDED: &str = "/realms/agents/.well-known/openid-configuration";

    fn path_issuer(server: &TestServer) -> String {
        server.url("/realms/agents/")
    }

    #[tokio::test]
    async fn a_path_issuer_is_discovered_from_rfc_8414_path_insertion() {
        let server = TestServer::start().await;
        let issuer = path_issuer(&server);
        server.reply(PATH_RFC8414, Reply::json(&document(&issuer).to_string()));
        server.reply(PATH_OIDC_INSERTED, Reply::json(&document(&issuer).to_string()));
        let metadata = discovered(&issuer, DiscoveryOptions::default())
            .await
            .unwrap();
        assert_eq!(metadata, expected(&issuer, server.url(PATH_RFC8414)));
        assert_eq!(server.requests(), [PATH_RFC8414]);
    }

    #[tokio::test]
    async fn a_path_issuer_falls_back_to_openid_connect_path_insertion() {
        let server = TestServer::start().await;
        let issuer = path_issuer(&server);
        server.reply(PATH_OIDC_INSERTED, Reply::json(&document(&issuer).to_string()));
        server.reply(PATH_OIDC_APPENDED, Reply::json(&document(&issuer).to_string()));
        let metadata = discovered(&issuer, DiscoveryOptions::default())
            .await
            .unwrap();
        assert_eq!(metadata, expected(&issuer, server.url(PATH_OIDC_INSERTED)));
        assert_eq!(server.requests(), [PATH_RFC8414, PATH_OIDC_INSERTED]);
    }

    #[tokio::test]
    async fn a_path_issuer_falls_back_to_openid_connect_path_appending() {
        let server = TestServer::start().await;
        let issuer = path_issuer(&server);
        server.reply(PATH_OIDC_APPENDED, Reply::json(&document(&issuer).to_string()));
        let metadata = discovered(&issuer, DiscoveryOptions::default())
            .await
            .unwrap();
        assert_eq!(metadata, expected(&issuer, server.url(PATH_OIDC_APPENDED)));
        assert_eq!(server.requests(), [PATH_RFC8414, PATH_OIDC_INSERTED, PATH_OIDC_APPENDED]);
    }

    #[tokio::test]
    async fn a_wrong_issuer_at_rfc_8414_path_insertion_falls_back_to_openid_connect_path_insertion() {
        let server = TestServer::start().await;
        let issuer = path_issuer(&server);
        server.reply(PATH_RFC8414, Reply::json(&document("https://other.example.com/realms/agents/").to_string()));
        server.reply(PATH_OIDC_INSERTED, Reply::json(&document(&issuer).to_string()));
        let metadata = discovered(&issuer, DiscoveryOptions::default())
            .await
            .unwrap();
        assert_eq!(metadata, expected(&issuer, server.url(PATH_OIDC_INSERTED)));
        assert_eq!(server.requests(), [PATH_RFC8414, PATH_OIDC_INSERTED]);
    }

    #[tokio::test]
    async fn when_all_three_path_issuer_documents_are_missing_the_status_failure_is_returned() {
        let server = TestServer::start().await;
        let error = discovered(&path_issuer(&server), DiscoveryOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.failure(), DiscoveryFailure::HttpStatus);
        assert_eq!(server.requests(), [PATH_RFC8414, PATH_OIDC_INSERTED, PATH_OIDC_APPENDED]);
    }

    #[tokio::test]
    async fn the_most_specific_failure_of_all_three_path_issuer_attempts_is_returned() {
        let server = TestServer::start().await;
        let issuer = path_issuer(&server);
        server.reply(PATH_RFC8414, Reply::status(404));
        server.reply(PATH_OIDC_INSERTED, Reply::json(&document("https://other.example.com").to_string()));
        server.reply(PATH_OIDC_APPENDED, Reply::status(404));
        let error = discovered(&issuer, DiscoveryOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.failure(), DiscoveryFailure::IssuerMismatch);
        assert!(
            error
                .detail()
                .starts_with(&server.url(PATH_OIDC_INSERTED)),
            "{}",
            error.detail()
        );
        assert_eq!(server.requests(), [PATH_RFC8414, PATH_OIDC_INSERTED, PATH_OIDC_APPENDED]);
    }

    #[tokio::test]
    async fn an_unreachable_first_path_issuer_url_ends_discovery_at_once() {
        let server = TestServer::start().await;
        let issuer = path_issuer(&server);
        server.reply(PATH_RFC8414, Reply::cut_short());
        server.reply(PATH_OIDC_INSERTED, Reply::json(&document(&issuer).to_string()));
        server.reply(PATH_OIDC_APPENDED, Reply::json(&document(&issuer).to_string()));
        let error = discovered(&issuer, DiscoveryOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.code(), "unreachable");
        assert_eq!(server.requests(), [PATH_RFC8414]);
    }

    #[tokio::test]
    async fn an_unreachable_third_path_issuer_url_is_returned_over_earlier_status_failures() {
        let server = TestServer::start().await;
        let issuer = path_issuer(&server);
        server.reply(PATH_RFC8414, Reply::status(404));
        server.reply(PATH_OIDC_INSERTED, Reply::status(404));
        server.reply(PATH_OIDC_APPENDED, Reply::cut_short());
        let error = discovered(&issuer, DiscoveryOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.code(), "unreachable");
        assert_eq!(server.requests(), [PATH_RFC8414, PATH_OIDC_INSERTED, PATH_OIDC_APPENDED]);
    }

    #[tokio::test]
    async fn an_issuer_with_whitespace_or_a_control_character_is_never_requested() {
        let server = TestServer::start().await;
        let base = server.base();
        server.reply(RFC8414, Reply::json(&document(base).to_string()));
        server.reply(OIDC, Reply::json(&document(base).to_string()));
        for issuer in [
            format!("{base}\n"),
            format!(" {base}"),
            format!("{base} "),
            format!("{base}/te\tnant"),
            format!("{base}/te\nnant"),
            format!("{base}/\0"),
            format!("{base}\r"),
        ] {
            for posture in [OPERATOR, STRICT] {
                let error = discover(&issuer, posture, DiscoveryOptions::default())
                    .await
                    .unwrap_err();
                assert_eq!(error.code(), "invalid_url", "{issuer:?} under {posture:?}");
            }
        }
        assert!(server.requests().is_empty(), "{:?}", server.requests());
        let metadata = discovered(base, DiscoveryOptions::default())
            .await
            .unwrap();
        assert_eq!(metadata, expected(base, server.url(RFC8414)));
        assert_eq!(server.requests(), [RFC8414]);
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
