//! Which Target challenges reach a caller. On an Access Point where the gateway
//! is the resource server, Target challenges other than `Payment` are addressed
//! to the gateway, so they never reach the caller, and a Target `401` left with
//! no challenge becomes a `502`. The gateway's own caller challenge is built by
//! `crate::proxy::caller_denial::challenge_failed_caller`. Over Fabric, a peer's
//! `401` and its `403` `insufficient_scope` are answered by
//! `crate::proxy::fabric_peer_refusal` before this filter runs.

use axum::http::header::WWW_AUTHENTICATE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;

use crate::protocols::protected_resource::is_gateway_challenge;

/// What [`strip_relayed_challenges`] removed from a Target response: the
/// scheme of each dropped challenge, in order, and whether the response
/// became a `502`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StrippedChallenges {
    pub dropped_schemes: Vec<String>,
    pub became_bad_gateway: bool,
}

/// Drops every relayed challenge except `Payment` from a response the gateway
/// did not challenge itself. A `401` left with no challenge becomes a `502`:
/// the Target refused the gateway, which the caller cannot fix, and a `401`
/// must carry a challenge.
pub fn strip_relayed_challenges(response: &mut Response) -> StrippedChallenges {
    if is_gateway_challenge(response)
        || !response
            .headers()
            .contains_key(WWW_AUTHENTICATE)
    {
        return StrippedChallenges::default();
    }
    let dropped_schemes = retain_payment_challenges(response.headers_mut());
    let became_bad_gateway = response.status() == StatusCode::UNAUTHORIZED
        && !response
            .headers()
            .contains_key(WWW_AUTHENTICATE);
    if became_bad_gateway {
        *response = crate::a2a::errors::create_error_response(
            StatusCode::BAD_GATEWAY,
            "The target refused the gateway's authorization",
        );
    }
    StrippedChallenges {
        dropped_schemes,
        became_bad_gateway,
    }
}

/// Keeps only the `Payment` challenges of every `WWW-Authenticate` value and
/// returns the schemes of the challenges it dropped. A value that lists
/// several challenges keeps its `Payment` ones; one that is not visible ASCII
/// is dropped unnamed.
fn retain_payment_challenges(headers: &mut HeaderMap) -> Vec<String> {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for value in headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
    {
        let (payment, others): (Vec<String>, Vec<String>) = challenges(value)
            .into_iter()
            .partition(|challenge| scheme(challenge).eq_ignore_ascii_case("payment"));
        dropped.extend(
            others
                .iter()
                .map(|challenge| scheme(challenge).to_string()),
        );
        if !payment.is_empty()
            && let Ok(value) = HeaderValue::from_str(&payment.join(", "))
        {
            kept.push(value);
        }
    }
    headers.remove(WWW_AUTHENTICATE);
    for value in kept {
        headers.append(WWW_AUTHENTICATE, value);
    }
    dropped
}

/// How a receiving gateway refused a request a sending gateway forwarded over
/// Fabric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRefusal {
    /// A `401` that carries no `Payment` challenge, with or without other
    /// challenges.
    Token,
    /// A `403` carrying a `Bearer` challenge with `error="insufficient_scope"`.
    Scope,
}

/// Whether a Fabric peer's answer refused the sending gateway's authorization.
/// `None` for every other answer, a policy `403` and a `401` or `402` that asks
/// for payment included. Schemes and parameter names compare case-insensitively,
/// the `error` value exactly (RFC 6750 section 3.1).
pub fn peer_refusal(
    status: StatusCode,
    headers: &HeaderMap,
) -> Option<PeerRefusal> {
    let challenges: Vec<String> = headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(challenges)
        .collect();
    if status == StatusCode::UNAUTHORIZED {
        let asks_for_payment = challenges
            .iter()
            .any(|challenge| scheme(challenge).eq_ignore_ascii_case("payment"));
        return (!asks_for_payment).then_some(PeerRefusal::Token);
    }
    if status == StatusCode::FORBIDDEN {
        let short_of_scope = challenges
            .iter()
            .any(|challenge| {
                scheme(challenge).eq_ignore_ascii_case("bearer")
                    && challenge_param(challenge, "error").as_deref() == Some("insufficient_scope")
            });
        return short_of_scope.then_some(PeerRefusal::Scope);
    }
    None
}

/// The value of auth-param `name` in one challenge (RFC 9110 section 11.2),
/// unquoted. A parameter inside another parameter's quoted value never matches.
fn challenge_param(
    challenge: &str,
    name: &str,
) -> Option<String> {
    let params = &challenge[scheme(challenge).len()..];
    list_elements(params)
        .into_iter()
        .find_map(|element| {
            let (key, value) = element.split_once('=')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| unquote(value.trim()))
        })
}

fn unquote(value: &str) -> String {
    let Some(inner) = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    else {
        return value.to_string();
    };
    let mut unquoted = String::with_capacity(inner.len());
    let mut escaped = false;
    for c in inner.chars() {
        if c == '\\' && !escaped {
            escaped = true;
            continue;
        }
        escaped = false;
        unquoted.push(c);
    }
    unquoted
}

fn scheme(challenge: &str) -> &str {
    challenge
        .split(' ')
        .next()
        .unwrap_or_default()
}

/// Splits one `WWW-Authenticate` value into its challenges (RFC 9110
/// section 11.6.1): a list element that starts with a token followed by a
/// space or nothing opens a challenge, and one that starts with `token =` is a
/// parameter of the challenge before it.
fn challenges(value: &str) -> Vec<String> {
    let mut challenges: Vec<String> = Vec::new();
    for element in list_elements(value) {
        if opens_challenge(&element) || challenges.is_empty() {
            challenges.push(element);
        } else if let Some(last) = challenges.last_mut() {
            last.push_str(", ");
            last.push_str(&element);
        }
    }
    challenges
}

fn opens_challenge(element: &str) -> bool {
    let token_end = element
        .find(|c: char| !is_token_char(c))
        .unwrap_or(element.len());
    token_end > 0
        && !element[token_end..]
            .trim_start()
            .starts_with('=')
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

/// The comma-separated elements of a header value, outside quoted strings,
/// trimmed and without empty ones.
fn list_elements(value: &str) -> Vec<String> {
    let mut elements = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in value.chars() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                elements.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    elements.push(current);
    elements
        .into_iter()
        .map(|element| element.trim().to_string())
        .filter(|element| !element.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use serde_json::{Value, json};

    use super::*;
    use crate::protocols::protected_resource::ResourceTokenError;
    use crate::protocols::protected_resource::fixtures::ISSUER;
    use crate::source_auth::declaration::Declaration;

    fn declaration_for(
        resource: &str,
        required_scopes: &[&str],
    ) -> Declaration {
        let required_scopes: Vec<String> = required_scopes
            .iter()
            .map(|scope| scope.to_string())
            .collect();
        Declaration {
            resource: resource.into(),
            authorization_servers: vec![ISSUER.into()],
            pin: None,
            advertised_scopes: required_scopes.clone(),
            required_scopes,
        }
    }

    async fn body_json(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    fn challenge_of(response: &Response) -> Option<&str> {
        response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
    }

    fn header_values(headers: &HeaderMap) -> Vec<&str> {
        headers
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .map(|value| value.to_str().expect("ascii"))
            .collect()
    }

    #[test]
    fn test_only_payment_challenges_are_relayed() {
        let mut headers = HeaderMap::new();
        for value in [
            "Bearer realm=\"upstream\", error=\"invalid_token\"",
            "Payment id=\"one\", realm=\"tg\", method=\"tempo\"",
            "DPoP algs=\"ES256\"",
            "Bearer resource_metadata=\"https://idp.internal/prm\", Payment id=\"two\", request=\"e30=\"",
            "Payment id=\"a,b\", description=\"say \\\"hi\\\", Bearer\"",
            "Basic realm=\"x\"",
        ] {
            headers.append(WWW_AUTHENTICATE, HeaderValue::from_static(value));
        }
        let dropped = retain_payment_challenges(&mut headers);
        assert_eq!(
            header_values(&headers),
            vec![
                "Payment id=\"one\", realm=\"tg\", method=\"tempo\"",
                "Payment id=\"two\", request=\"e30=\"",
                "Payment id=\"a,b\", description=\"say \\\"hi\\\", Bearer\"",
            ]
        );
        assert_eq!(dropped, ["Bearer", "DPoP", "Bearer", "Basic"]);
    }

    #[test]
    fn test_a_response_without_payment_challenges_loses_every_challenge() {
        let mut headers = HeaderMap::new();
        headers.append(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        headers.append(WWW_AUTHENTICATE, HeaderValue::from_static("Negotiate abc=="));
        assert_eq!(retain_payment_challenges(&mut headers), ["Bearer", "Negotiate"]);
        assert!(header_values(&headers).is_empty());
    }

    #[test]
    fn test_the_gateways_own_challenge_survives_the_filter() {
        let declarations = [
            declaration_for("https://gateway.example/mcp/alpha", &["tools"]),
            declaration_for("https://gw.example/a2a/buyer", &["agent.invoke", "agent.read"]),
        ];
        for declaration in declarations {
            let mut own = declaration.challenge(ResourceTokenError::Missing);
            assert_eq!(strip_relayed_challenges(&mut own), StrippedChallenges::default());
            assert_eq!(own.status(), StatusCode::UNAUTHORIZED);
            assert!(
                challenge_of(&own).is_some_and(|value| value.starts_with("Bearer resource_metadata=")),
                "{:?}",
                challenge_of(&own)
            );
        }

        let mut upstream = relayed(StatusCode::OK, &["Bearer realm=\"upstream\""]);
        assert_eq!(
            strip_relayed_challenges(&mut upstream),
            StrippedChallenges {
                dropped_schemes: vec!["Bearer".into()],
                became_bad_gateway: false,
            }
        );
        assert_eq!(challenge_of(&upstream), None);
    }

    fn relayed(
        status: StatusCode,
        challenges: &[&'static str],
    ) -> Response {
        let mut response = Response::new(Body::from("{\"upstream\":\"https://idp.internal\"}"));
        *response.status_mut() = status;
        for challenge in challenges {
            response
                .headers_mut()
                .append(WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
        }
        response
    }

    #[tokio::test]
    async fn test_a_relayed_401_left_without_a_challenge_becomes_a_502() {
        let mut response = relayed(StatusCode::UNAUTHORIZED, &["Bearer realm=\"upstream\"", "DPoP algs=\"ES256\""]);
        assert_eq!(
            strip_relayed_challenges(&mut response),
            StrippedChallenges {
                dropped_schemes: vec!["Bearer".into(), "DPoP".into()],
                became_bad_gateway: true,
            }
        );
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(challenge_of(&response), None);
        assert_eq!(
            body_json(response).await,
            json!({
                "type": "https://a2a-protocol.org/errors/proxy-error",
                "title": "Bad Gateway",
                "status": 502,
                "detail": "The target refused the gateway's authorization",
            })
        );
    }

    #[tokio::test]
    async fn test_a_relayed_401_or_402_with_a_payment_challenge_keeps_its_status_and_body() {
        for status in [StatusCode::UNAUTHORIZED, StatusCode::PAYMENT_REQUIRED] {
            let mut response =
                relayed(status, &["Bearer realm=\"upstream\"", "Payment id=\"p\"", "DPoP algs=\"ES256\""]);
            assert_eq!(
                strip_relayed_challenges(&mut response),
                StrippedChallenges {
                    dropped_schemes: vec!["Bearer".into(), "DPoP".into()],
                    became_bad_gateway: false,
                }
            );
            assert_eq!(response.status(), status);
            assert_eq!(header_values(response.headers()), ["Payment id=\"p\""]);
            assert_eq!(body_json(response).await["upstream"], "https://idp.internal");
        }
    }

    #[tokio::test]
    async fn test_statuses_other_than_401_and_unchallenged_401s_keep_their_status() {
        let mut forbidden = relayed(StatusCode::FORBIDDEN, &["Bearer error=\"insufficient_scope\""]);
        let stripped = strip_relayed_challenges(&mut forbidden);
        assert_eq!(stripped.dropped_schemes, ["Bearer"]);
        assert!(!stripped.became_bad_gateway);
        assert_eq!((forbidden.status(), challenge_of(&forbidden)), (StatusCode::FORBIDDEN, None));

        let mut unchallenged = relayed(StatusCode::UNAUTHORIZED, &[]);
        assert_eq!(strip_relayed_challenges(&mut unchallenged), StrippedChallenges::default());
        assert_eq!(unchallenged.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(unchallenged).await["upstream"], "https://idp.internal");
    }

    fn peer_headers(values: &[&'static str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(WWW_AUTHENTICATE, HeaderValue::from_static(value));
        }
        headers
    }

    const BEARER_INSUFFICIENT_SCOPE: &str = "Bearer realm=\"agent-gateway\", error=\"insufficient_scope\"";
    const PAYMENT: &str = "Payment id=\"p1\", realm=\"tg\", method=\"tempo\"";

    #[test]
    fn test_a_peer_401_without_a_payment_challenge_is_a_token_refusal() {
        let cases: [&[&'static str]; 6] = [
            &[],
            &["Bearer realm=\"agent-gateway\""],
            &["Bearer realm=\"agent-gateway\", error=\"invalid_token\""],
            &["Bearer resource_metadata=\"https://gw2.example/.well-known/oauth-protected-resource/a2a\""],
            &["DPoP algs=\"ES256\""],
            &["Basic realm=\"x\""],
        ];
        for values in cases {
            assert_eq!(
                peer_refusal(StatusCode::UNAUTHORIZED, &peer_headers(values)),
                Some(PeerRefusal::Token),
                "{values:?}"
            );
        }
    }

    #[test]
    fn test_a_peer_401_with_a_payment_challenge_is_not_a_peer_refusal() {
        let cases: [&[&'static str]; 3] = [
            &[PAYMENT],
            &["Bearer realm=\"agent-gateway\", Payment id=\"p1\", request=\"e30=\""],
            &["Bearer realm=\"agent-gateway\"", PAYMENT],
        ];
        for values in cases {
            assert_eq!(peer_refusal(StatusCode::UNAUTHORIZED, &peer_headers(values)), None, "{values:?}");
        }
    }

    #[test]
    fn test_a_peer_403_with_a_bearer_insufficient_scope_challenge_is_a_scope_refusal() {
        let cases: [&[&'static str]; 4] = [
            &[BEARER_INSUFFICIENT_SCOPE],
            &["bearer error=insufficient_scope"],
            &["Bearer scope=\"a b\", error=\"insufficient_scope\""],
            &[PAYMENT, BEARER_INSUFFICIENT_SCOPE],
        ];
        for values in cases {
            assert_eq!(
                peer_refusal(StatusCode::FORBIDDEN, &peer_headers(values)),
                Some(PeerRefusal::Scope),
                "{values:?}"
            );
        }
    }

    #[test]
    fn test_a_peer_403_without_a_bearer_insufficient_scope_challenge_is_not_a_peer_refusal() {
        let cases: [&[&'static str]; 6] = [
            &[],
            &["Bearer error=\"invalid_token\""],
            &["DPoP error=\"insufficient_scope\""],
            &["Bearer error_description=\"insufficient_scope\""],
            &["Bearer realm=\"error=\\\"insufficient_scope\\\"\""],
            &["Bearer error=\"INSUFFICIENT_SCOPE\""],
        ];
        for values in cases {
            assert_eq!(peer_refusal(StatusCode::FORBIDDEN, &peer_headers(values)), None, "{values:?}");
        }
    }

    #[test]
    fn test_other_peer_statuses_are_not_peer_refusals() {
        let cases: [(StatusCode, &[&'static str]); 6] = [
            (StatusCode::OK, &[]),
            (StatusCode::PAYMENT_REQUIRED, &[BEARER_INSUFFICIENT_SCOPE]),
            (StatusCode::NOT_FOUND, &[]),
            (StatusCode::INTERNAL_SERVER_ERROR, &[]),
            (StatusCode::BAD_GATEWAY, &[]),
            (StatusCode::SERVICE_UNAVAILABLE, &["Bearer realm=\"agent-gateway\""]),
        ];
        for (status, values) in cases {
            assert_eq!(peer_refusal(status, &peer_headers(values)), None, "{status}");
        }
    }
}
