//! What a refused caller receives at an Access Point, and which Target
//! challenges reach it.
//!
//! A caller whose source authentication failed, refused on a declaring Access
//! Point, receives the declaration's RFC 6750 challenge naming its protected
//! resource metadata. Every other refusal keeps the 403 of the stage that
//! refused it. On an Access Point where the gateway is the resource server,
//! Target challenges other than `Payment` are addressed to the gateway, so they
//! never reach the caller, and a Target `401` left with no challenge becomes a
//! `502`.

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;

use crate::protocols::protected_resource::{ResourceTokenError, is_gateway_challenge};
use crate::source_auth::declaration::Declaration;
use crate::surface_context::SourceAuthContext;

/// The stage that refused a caller. It names the body of the refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerDenial {
    AppliancePolicy,
    GatewayPolicy,
    SurfacePolicy,
    SurfacePolicyUnloaded,
    IdentityRequired,
}

impl CallerDenial {
    /// The stage's `403`.
    fn response(self) -> Response {
        let status = StatusCode::FORBIDDEN;
        let title = status
            .canonical_reason()
            .unwrap_or("Error");
        let proxy_error = |detail: &str| crate::a2a::errors::proxy_error_body(status, detail);
        let surface_error = |message: &str| serde_json::json!({ "error": title, "message": message });
        let (content_type, body) = match self {
            Self::AppliancePolicy => {
                ("application/problem+json", proxy_error("Request blocked by appliance-wide policy"))
            }
            Self::GatewayPolicy => ("application/problem+json", proxy_error("Request blocked by gateway policy")),
            Self::SurfacePolicy => ("application/json", surface_error("Agent trust policy denied the request")),
            Self::SurfacePolicyUnloaded => (
                "application/json",
                surface_error("OPA policy enforcement is enabled but no policy is loaded for this channel"),
            ),
            Self::IdentityRequired => (
                "application/problem+json",
                serde_json::json!({
                    "type": "https://affinidi.com/atg/errors/identity-required",
                    "title": "Identity Required for Credential Delegation",
                    "status": status.as_u16(),
                    "detail": "This channel requires credential delegation which needs authenticated source identity. \
                               Configure source authentication and agent identity management on this channel.",
                }),
            ),
        };
        let mut response = Response::new(Body::from(body.to_string()));
        *response.status_mut() = status;
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
        response
    }
}

/// The response for a refused caller. A caller that failed source
/// authentication on a declaring Access Point gets the declaration's challenge,
/// as at the source-auth stage. Every other caller gets the stage's 403.
pub fn caller_deny_response(
    denial: CallerDenial,
    declaration: Option<&Declaration>,
    source_auth: Option<&SourceAuthContext>,
) -> Response {
    match (declaration, source_auth) {
        (Some(declaration), Some(SourceAuthContext::Failed { kind, .. })) => {
            declaration.challenge(ResourceTokenError::from(*kind))
        }
        _ => denial.response(),
    }
}

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
    use axum::http::header::CACHE_CONTROL;
    use serde_json::{Value, json};

    use super::*;
    use crate::config::agent_surface::AgentSurface;
    use crate::protocols::protected_resource::fixtures::{
        ISSUER, discovery_network, discovery_surface, jwt_bearer_method,
    };
    use crate::source_auth::declaration::{DeclarationOutcome, resolve_surface_declaration};
    use crate::source_auth::errors::SourceAuthFailureKind;

    const RESOURCE: &str = "https://gateway.example/mcp/alpha";
    const METADATA: &str = "https://gateway.example/.well-known/oauth-protected-resource/mcp/alpha";

    fn declaration_of(surface: AgentSurface) -> Declaration {
        match resolve_surface_declaration(&surface, None, &discovery_network()) {
            DeclarationOutcome::Declare(declaration) => declaration,
            other => panic!("expected a declaration, got {other:?}"),
        }
    }

    fn declaration() -> Declaration {
        let mut method = jwt_bearer_method();
        method["required_scopes"] = json!(["tools"]);
        declaration_of(discovery_surface(
            method,
            Some(json!({"resource": RESOURCE, "authorization_servers": [ISSUER], "scopes": ["tools"]})),
        ))
    }

    fn failed(kind: SourceAuthFailureKind) -> SourceAuthContext {
        SourceAuthContext::Failed {
            attempted_method: "jwt_bearer".into(),
            kind,
            reason: "x".into(),
        }
    }

    async fn body_json(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    fn header(
        response: &Response,
        name: axum::http::HeaderName,
    ) -> Option<&str> {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
    }

    fn challenge_of(response: &Response) -> Option<&str> {
        header(response, WWW_AUTHENTICATE)
    }

    #[tokio::test]
    async fn test_a_failed_caller_on_a_declaring_access_point_gets_its_challenge_at_every_stage() {
        let declaration = declaration();
        for (denial, kind, challenge) in [
            (
                CallerDenial::SurfacePolicy,
                SourceAuthFailureKind::Missing,
                format!("Bearer resource_metadata=\"{METADATA}\", scope=\"tools\""),
            ),
            (
                CallerDenial::GatewayPolicy,
                SourceAuthFailureKind::Invalid,
                format!("Bearer resource_metadata=\"{METADATA}\", error=\"invalid_token\", scope=\"tools\""),
            ),
        ] {
            let response = caller_deny_response(denial, Some(&declaration), Some(&failed(kind)));
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{denial:?}");
            assert_eq!(challenge_of(&response), Some(challenge.as_str()));
            assert!(is_gateway_challenge(&response));
            assert_eq!(header(&response, CONTENT_TYPE), Some("application/problem+json"));
            assert_eq!(header(&response, CACHE_CONTROL), Some("no-store"));
            assert_eq!(
                body_json(response).await,
                json!({
                    "type": "about:blank",
                    "title": "Unauthorized",
                    "status": 401,
                    "detail": "A bearer token from an authorization server in the protected resource metadata is required",
                })
            );
        }
    }

    #[tokio::test]
    async fn test_a_failed_caller_without_a_declaration_keeps_the_stage_403() {
        for kind in [SourceAuthFailureKind::Missing, SourceAuthFailureKind::Invalid] {
            let response = caller_deny_response(CallerDenial::SurfacePolicy, None, Some(&failed(kind)));
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{kind:?}");
            assert_eq!(challenge_of(&response), None, "{kind:?}");
            assert_eq!(header(&response, CACHE_CONTROL), None, "{kind:?}");
            assert!(!is_gateway_challenge(&response), "{kind:?}");
            assert_eq!(
                body_json(response).await,
                json!({"error": "Forbidden", "message": "Agent trust policy denied the request"})
            );
        }
    }

    #[tokio::test]
    async fn test_an_authenticated_or_anonymous_caller_keeps_the_stage_403() {
        let declaration = declaration();
        let authenticated = SourceAuthContext::ApiKey { key_name: "k".into() };
        for source_auth in [None, Some(&authenticated)] {
            let response = caller_deny_response(CallerDenial::GatewayPolicy, Some(&declaration), source_auth);
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(challenge_of(&response), None);
            assert_eq!(
                body_json(response).await,
                json!({
                    "type": "https://a2a-protocol.org/errors/proxy-error",
                    "title": "Forbidden",
                    "status": 403,
                    "detail": "Request blocked by gateway policy",
                })
            );
        }
    }

    #[tokio::test]
    async fn test_each_stage_keeps_its_403_body() {
        let cases = [
            (CallerDenial::AppliancePolicy, "detail", "Request blocked by appliance-wide policy"),
            (
                CallerDenial::SurfacePolicyUnloaded,
                "message",
                "OPA policy enforcement is enabled but no policy is loaded for this channel",
            ),
        ];
        for (denial, field, text) in cases {
            let response = caller_deny_response(denial, None, None);
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{denial:?}");
            assert_eq!(body_json(response).await[field], text, "{denial:?}");
        }
        let body = body_json(caller_deny_response(CallerDenial::IdentityRequired, None, None)).await;
        assert_eq!(body["type"], "https://affinidi.com/atg/errors/identity-required");
        assert_eq!(body["status"], 403);
    }

    #[test]
    fn test_a_root_route_resource_names_the_bare_metadata_path() {
        let mut root = discovery_surface(
            jwt_bearer_method(),
            Some(json!({"resource": "https://gateway.example/", "authorization_servers": [ISSUER]})),
        );
        root.access_point.route = "/".into();
        let root = declaration_of(root);
        let response = caller_deny_response(
            CallerDenial::SurfacePolicy,
            Some(&root),
            Some(&failed(SourceAuthFailureKind::Missing)),
        );
        assert_eq!(
            challenge_of(&response),
            Some("Bearer resource_metadata=\"https://gateway.example/.well-known/oauth-protected-resource\"")
        );
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
        let declaration = declaration();
        let mut own = caller_deny_response(
            CallerDenial::GatewayPolicy,
            Some(&declaration),
            Some(&failed(SourceAuthFailureKind::Missing)),
        );
        assert_eq!(strip_relayed_challenges(&mut own), StrippedChallenges::default());
        assert_eq!(own.status(), StatusCode::UNAUTHORIZED);
        assert!(
            challenge_of(&own).is_some_and(|value| value.starts_with("Bearer resource_metadata=")),
            "{:?}",
            challenge_of(&own)
        );

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
}
