//! Browser login handoff for the `fabric` CLI: loopback redirect plus PKCE.
//!
//! The session token is returned only on the back-channel exchange, never in a browser URL.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::Query,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::Engine;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::debug;
use uuid::Uuid;

use crate::auth::session::{SessionManager, TermsSessionGate};
use crate::auth_manager::middleware::extract_session_token_from_headers;

/// Dashboard page that asks the signed-in user to approve the CLI login.
const CONSENT_PAGE_PATH: &str = "/cli-consent";

const CODE_TTL: Duration = Duration::from_secs(120);

const MAX_PARAM_LEN: usize = 256;

/// Ports below 1024 are privileged, so a crafted URL cannot aim the redirect at one.
const MIN_LOOPBACK_PORT: u16 = 1024;

const PKCE_CHALLENGE_LEN: usize = 43;

const PKCE_VERIFIER_LEN: std::ops::RangeInclusive<usize> = 43..=128;

const CODE_LEN: usize = 36;

/// Caps memory held by unredeemed codes.
const MAX_PENDING_CODES: usize = 1000;

struct PendingCliAuth {
    code_challenge: String,
    session_token: String,
    expires_at: Instant,
}

#[derive(Default)]
pub struct CliLoginStore {
    entries: DashMap<String, PendingCliAuth>,
}

impl CliLoginStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn create(
        &self,
        code_challenge: String,
        session_token: String,
    ) -> Option<String> {
        let now = Instant::now();
        self.entries
            .retain(|_, pending| pending.expires_at > now);
        if self.entries.len() >= MAX_PENDING_CODES {
            return None;
        }
        let code = Uuid::new_v4().to_string();
        self.entries.insert(
            code.clone(),
            PendingCliAuth {
                code_challenge,
                session_token,
                expires_at: now + CODE_TTL,
            },
        );
        Some(code)
    }

    /// The code is consumed even when the verifier is wrong, so it cannot be guessed against.
    fn redeem(
        &self,
        code: &str,
        verifier: &str,
    ) -> Option<String> {
        let (_, pending) = self.entries.remove(code)?;
        if Instant::now() >= pending.expires_at {
            return None;
        }
        let expected = pkce_challenge_s256(verifier);
        if !constant_time_eq(
            expected.as_bytes(),
            pending
                .code_challenge
                .as_bytes(),
        ) {
            return None;
        }
        Some(pending.session_token)
    }
}

pub fn cli_login_router(session_manager: Arc<SessionManager>) -> Router {
    Router::new()
        .route("/auth/cli/authorize", get(authorize))
        .route("/auth/cli/consent", post(consent))
        .route("/auth/cli/exchange", post(exchange))
        .layer(Extension(session_manager))
        .layer(Extension(Arc::new(CliLoginStore::new())))
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    port: u16,
    state: String,
    challenge: String,
}

fn is_valid_login_request(
    port: u16,
    state: &str,
    challenge: &str,
) -> bool {
    port >= MIN_LOOPBACK_PORT && is_valid_param(state) && is_valid_challenge(challenge)
}

/// Sends a signed-in user to the consent page. No code is issued until the user approves there.
pub async fn authorize(
    headers: HeaderMap,
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    if !is_valid_login_request(query.port, &query.state, &query.challenge) {
        return (StatusCode::BAD_REQUEST, "invalid CLI login request").into_response();
    }

    let signed_in = match extract_session_token_from_headers(&headers) {
        Some(token) => session_manager
            .validate_session(&token)
            .await
            .is_some(),
        None => false,
    };

    let target = if signed_in {
        build_consent_redirect(query.port, &query.state, &query.challenge)
    } else {
        build_login_bounce(query.port, &query.state, &query.challenge)
    };
    no_store(Redirect::to(&target).into_response())
}

#[derive(Debug, Deserialize)]
pub struct ConsentRequest {
    port: u16,
    state: String,
    challenge: String,
}

#[derive(Debug, Serialize)]
pub struct ConsentResponse {
    pub redirect_url: String,
}

/// Issues the code once the signed-in user approves. The cookie is `SameSite=Strict`; this also
/// requires a same-origin JSON request so a page on another origin cannot trigger an approval.
pub async fn consent(
    headers: HeaderMap,
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Extension(store): Extension<Arc<CliLoginStore>>,
    body: Bytes,
) -> Response {
    if !is_same_origin_request(&headers) {
        return (StatusCode::FORBIDDEN, "cross-origin request rejected").into_response();
    }
    if !is_json_request(&headers) {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "expected application/json").into_response();
    }

    let session = match extract_session_token_from_headers(&headers) {
        Some(token) => session_manager
            .validate_session_record(&token)
            .await
            .map(|session| (token, session)),
        None => None,
    };
    let Some((token, session)) = session else {
        return no_store((StatusCode::UNAUTHORIZED, "sign in required").into_response());
    };
    if session.terms_gate == TermsSessionGate::ConsentPending {
        return no_store((StatusCode::FORBIDDEN, "terms acceptance required").into_response());
    }

    let Ok(request) = serde_json::from_slice::<ConsentRequest>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid CLI login request").into_response();
    };
    if !is_valid_login_request(request.port, &request.state, &request.challenge) {
        return (StatusCode::BAD_REQUEST, "invalid CLI login request").into_response();
    }

    let Some(code) = store.create(request.challenge, token) else {
        return (StatusCode::TOO_MANY_REQUESTS, "too many pending CLI logins").into_response();
    };
    debug!("Issued CLI login code for loopback port {}", request.port);
    no_store(
        Json(ConsentResponse {
            redirect_url: build_loopback_redirect(request.port, &code, &request.state),
        })
        .into_response(),
    )
}

fn is_json_request(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| {
            media_type
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
}

/// Browsers always send `Sec-Fetch-Site`; `Origin` against `Host` covers clients that do not.
fn is_same_origin_request(headers: &HeaderMap) -> bool {
    if let Some(site) = headers.get("sec-fetch-site") {
        return site.as_bytes() == b"same-origin";
    }
    let origin_authority = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .and_then(|origin| origin.split_once("://"))
        .map(|(_, authority)| authority);
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    matches!((origin_authority, host), (Some(origin), Some(host)) if origin.eq_ignore_ascii_case(host))
}

#[derive(Debug, Deserialize)]
pub struct ExchangeRequest {
    code: String,
    verifier: String,
}

#[derive(Debug, Serialize)]
pub struct ExchangeResponse {
    pub session_token: String,
}

pub async fn exchange(
    Extension(store): Extension<Arc<CliLoginStore>>,
    Json(request): Json<ExchangeRequest>,
) -> Response {
    if request.code.len() != CODE_LEN || !is_valid_verifier(&request.verifier) {
        return (StatusCode::BAD_REQUEST, "invalid exchange request").into_response();
    }
    match store.redeem(&request.code, &request.verifier) {
        Some(session_token) => no_store(Json(ExchangeResponse { session_token }).into_response()),
        None => (StatusCode::BAD_REQUEST, "invalid or expired authorization code").into_response(),
    }
}

fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn pkce_challenge_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn constant_time_eq(
    a: &[u8],
    b: &[u8],
) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The host is fixed to `127.0.0.1` so a crafted request cannot redirect to another host.
fn build_loopback_redirect(
    port: u16,
    code: &str,
    state: &str,
) -> String {
    format!(
        "http://127.0.0.1:{}/callback?code={}&state={}",
        port,
        urlencoding::encode(code),
        urlencoding::encode(state),
    )
}

fn build_consent_redirect(
    port: u16,
    state: &str,
    challenge: &str,
) -> String {
    format!(
        "{}?port={}&state={}&challenge={}",
        CONSENT_PAGE_PATH,
        port,
        urlencoding::encode(state),
        urlencoding::encode(challenge),
    )
}

fn build_login_bounce(
    port: u16,
    state: &str,
    challenge: &str,
) -> String {
    let next = format!(
        "/api/auth/cli/authorize?port={}&state={}&challenge={}",
        port,
        urlencoding::encode(state),
        urlencoding::encode(challenge),
    );
    format!("/login?next={}", urlencoding::encode(&next))
}

fn is_valid_param(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_PARAM_LEN
}

fn is_valid_challenge(value: &str) -> bool {
    value.len() == PKCE_CHALLENGE_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_valid_verifier(value: &str) -> bool {
    PKCE_VERIFIER_LEN.contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const TEST_VERIFIER: &str = "verifier-value-that-is-long-enough-1234567890";

    fn test_challenge() -> String {
        pkce_challenge_s256(TEST_VERIFIER)
    }

    #[test]
    fn pkce_challenge_matches_known_vector() {
        // RFC 7636 Appendix B verifier/challenge pair.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_challenge_s256(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn redeem_returns_token_for_matching_verifier() {
        let store = CliLoginStore::new();
        let verifier = "verifier-value-that-is-long-enough-1234567890";
        let code = store
            .create(pkce_challenge_s256(verifier), "session-abc".to_string())
            .unwrap();

        assert_eq!(
            store
                .redeem(&code, verifier)
                .as_deref(),
            Some("session-abc")
        );
    }

    #[test]
    fn redeem_is_single_use() {
        let store = CliLoginStore::new();
        let verifier = "verifier-value-that-is-long-enough-1234567890";
        let code = store
            .create(pkce_challenge_s256(verifier), "session-abc".to_string())
            .unwrap();

        assert!(
            store
                .redeem(&code, verifier)
                .is_some()
        );
        assert!(
            store
                .redeem(&code, verifier)
                .is_none()
        );
    }

    #[test]
    fn redeem_rejects_wrong_verifier() {
        let store = CliLoginStore::new();
        let code = store
            .create(pkce_challenge_s256("the-real-verifier-1234567890abcdef"), "session-abc".to_string())
            .unwrap();

        assert!(
            store
                .redeem(&code, "a-different-verifier-000000000000")
                .is_none()
        );
    }

    #[test]
    fn create_purges_expired_entries() {
        let store = CliLoginStore::new();
        store.entries.insert(
            "stale".to_string(),
            PendingCliAuth {
                code_challenge: "ch".to_string(),
                session_token: "session-old".to_string(),
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );

        store
            .create("ch".to_string(), "session-new".to_string())
            .unwrap();

        assert!(
            !store
                .entries
                .contains_key("stale")
        );
        assert_eq!(store.entries.len(), 1);
    }

    #[test]
    fn redeem_rejects_expired_code() {
        let store = CliLoginStore::new();
        let verifier = "verifier-value-that-is-long-enough-1234567890";
        let code = Uuid::new_v4().to_string();
        store.entries.insert(
            code.clone(),
            PendingCliAuth {
                code_challenge: pkce_challenge_s256(verifier),
                session_token: "session-abc".to_string(),
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );

        assert!(
            store
                .redeem(&code, verifier)
                .is_none()
        );
    }

    #[test]
    fn loopback_redirect_is_pinned_to_localhost() {
        let url = build_loopback_redirect(52111, "code-123", "state value/&");
        assert!(url.starts_with("http://127.0.0.1:52111/callback?code=code-123&state="));
        assert!(url.contains("state%20value%2F%26"));
    }

    #[test]
    fn login_bounce_targets_same_origin_authorize() {
        let bounce = build_login_bounce(52111, "st", "ch");
        assert!(bounce.starts_with("/login?next="));
        let next = bounce
            .strip_prefix("/login?next=")
            .unwrap();
        let decoded = urlencoding::decode(next).unwrap();
        assert_eq!(decoded, "/api/auth/cli/authorize?port=52111&state=st&challenge=ch");
    }

    #[test]
    fn challenge_validation_rejects_non_base64url() {
        assert!(is_valid_challenge(&format!("{}-_", "A1".repeat(20) + "b")));
        assert!(!is_valid_challenge(&format!("{} ", "a".repeat(42))));
        assert!(!is_valid_challenge(&format!("{}/", "a".repeat(42))));
        assert!(!is_valid_challenge(""));
    }

    #[test]
    fn challenge_validation_requires_exactly_43_characters() {
        assert!(is_valid_challenge(&"a".repeat(43)));
        assert!(!is_valid_challenge(&"a".repeat(42)));
        assert!(!is_valid_challenge(&"a".repeat(44)));
        assert!(is_valid_challenge(&test_challenge()));
    }

    #[test]
    fn verifier_validation_enforces_length_bounds() {
        assert!(!is_valid_verifier(&"a".repeat(42)));
        assert!(is_valid_verifier(&"a".repeat(43)));
        assert!(is_valid_verifier(&"a".repeat(128)));
        assert!(!is_valid_verifier(&"a".repeat(129)));
    }

    #[test]
    fn verifier_validation_enforces_character_set() {
        assert!(is_valid_verifier(&format!("{}-._~", "a".repeat(43))));
        assert!(!is_valid_verifier(&format!("{}+", "a".repeat(43))));
        assert!(!is_valid_verifier(&format!("{}/", "a".repeat(43))));
        assert!(!is_valid_verifier(&format!("{} ", "a".repeat(43))));
    }

    #[test]
    fn create_refuses_new_codes_at_the_pending_cap() {
        let store = CliLoginStore::new();
        for _ in 0..MAX_PENDING_CODES {
            assert!(
                store
                    .create("ch".to_string(), "session".to_string())
                    .is_some()
            );
        }
        assert!(
            store
                .create("ch".to_string(), "session".to_string())
                .is_none()
        );
        assert_eq!(store.entries.len(), MAX_PENDING_CODES);
    }

    fn authorize_uri(port: u16) -> String {
        format!("/auth/cli/authorize?port={port}&state={}&challenge={}", "s".repeat(43), test_challenge())
    }

    async fn get_authorize(
        router: &Router,
        port: u16,
        session: Option<&str>,
    ) -> Response {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(authorize_uri(port));
        if let Some(token) = session {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        router
            .clone()
            .oneshot(
                request
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    fn consent_body(port: u16) -> String {
        serde_json::json!({ "port": port, "state": "s".repeat(43), "challenge": test_challenge() }).to_string()
    }

    async fn post_consent(
        router: &Router,
        body: String,
        session: Option<&str>,
        extra_headers: &[(&str, &str)],
    ) -> Response {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/auth/cli/consent");
        if let Some(token) = session {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        for (name, value) in extra_headers {
            request = request.header(*name, *value);
        }
        router
            .clone()
            .oneshot(
                request
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    const SAME_ORIGIN_JSON: [(&str, &str); 2] =
        [("content-type", "application/json"), ("sec-fetch-site", "same-origin")];

    async fn consent_redirect_url(response: Response) -> String {
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        json["redirect_url"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn code_from_redirect(redirect: &str) -> String {
        redirect
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_string()
    }

    async fn post_exchange(
        router: &Router,
        code: &str,
        verifier: &str,
    ) -> Response {
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/auth/cli/exchange")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::json!({ "code": code, "verifier": verifier }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    fn location(response: &Response) -> String {
        response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn authorize_rejects_privileged_ports_and_accepts_1024() {
        let router = cli_login_router(Arc::new(SessionManager::new()));

        for port in [0, 80, 1023] {
            let response = get_authorize(&router, port, None).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "port {port}");
        }
        let response = get_authorize(&router, 1024, None).await;
        assert!(
            response
                .status()
                .is_redirection()
        );
    }

    #[tokio::test]
    async fn authorize_rejects_a_challenge_of_the_wrong_length() {
        let router = cli_login_router(Arc::new(SessionManager::new()));
        let response = router
            .oneshot(
                Request::builder()
                    .uri(format!("/auth/cli/authorize?port=52111&state=st&challenge={}", "a".repeat(42)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn consent_answers_429_when_the_pending_cap_is_reached() {
        let manager = Arc::new(SessionManager::new());
        let token = manager
            .create_session("alice".to_string(), "user-1".to_string())
            .await;
        let store = Arc::new(CliLoginStore::new());
        for _ in 0..MAX_PENDING_CODES {
            store
                .create("ch".to_string(), "session".to_string())
                .unwrap();
        }
        let router = Router::new()
            .route("/auth/cli/consent", post(consent))
            .layer(Extension(manager))
            .layer(Extension(store));

        let response = post_consent(&router, consent_body(52111), Some(&token), &SAME_ORIGIN_JSON).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn authorize_with_a_session_redirects_to_consent_without_issuing_a_code() {
        let manager = Arc::new(SessionManager::new());
        let token = manager
            .create_session("alice".to_string(), "user-1".to_string())
            .await;
        let router = cli_login_router(manager);

        let response = get_authorize(&router, 52111, Some(&token)).await;
        let target = location(&response);
        assert_eq!(target, format!("/cli-consent?port=52111&state={}&challenge={}", "s".repeat(43), test_challenge()));
        assert!(!target.contains("code="));
    }

    #[tokio::test]
    async fn consent_requires_a_session() {
        let router = cli_login_router(Arc::new(SessionManager::new()));
        let response = post_consent(&router, consent_body(52111), None, &SAME_ORIGIN_JSON).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = post_consent(&router, consent_body(52111), Some("not-a-session"), &SAME_ORIGIN_JSON).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn consent_rejects_cross_origin_requests() {
        let manager = Arc::new(SessionManager::new());
        let token = manager
            .create_session("alice".to_string(), "user-1".to_string())
            .await;
        let router = cli_login_router(manager);

        let cases: [&[(&str, &str)]; 4] = [
            &[("content-type", "application/json"), ("sec-fetch-site", "cross-site")],
            &[("content-type", "application/json"), ("sec-fetch-site", "same-site")],
            &[("content-type", "application/json"), ("origin", "https://evil.example"), ("host", "gateway.example")],
            &[("content-type", "application/json")],
        ];
        for headers in cases {
            let response = post_consent(&router, consent_body(52111), Some(&token), headers).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{headers:?}");
        }
    }

    #[tokio::test]
    async fn consent_accepts_a_matching_origin_and_host_without_fetch_metadata() {
        let manager = Arc::new(SessionManager::new());
        let token = manager
            .create_session("alice".to_string(), "user-1".to_string())
            .await;
        let router = cli_login_router(manager);

        let headers = [
            ("content-type", "application/json; charset=utf-8"),
            ("origin", "https://gateway.example"),
            ("host", "gateway.example"),
        ];
        let response = post_consent(&router, consent_body(52111), Some(&token), &headers).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn consent_rejects_non_json_content_types() {
        let manager = Arc::new(SessionManager::new());
        let token = manager
            .create_session("alice".to_string(), "user-1".to_string())
            .await;
        let router = cli_login_router(manager);

        for content_type in ["text/plain", "application/x-www-form-urlencoded"] {
            let headers = [("content-type", content_type), ("sec-fetch-site", "same-origin")];
            let response = post_consent(&router, consent_body(52111), Some(&token), &headers).await;
            assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE, "{content_type}");
        }
        let response =
            post_consent(&router, consent_body(52111), Some(&token), &[("sec-fetch-site", "same-origin")]).await;
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn consent_rejects_invalid_port_state_and_challenge() {
        let manager = Arc::new(SessionManager::new());
        let token = manager
            .create_session("alice".to_string(), "user-1".to_string())
            .await;
        let router = cli_login_router(manager);

        let bad_bodies = [
            consent_body(80),
            consent_body(1023),
            serde_json::json!({ "port": 52111, "state": "st", "challenge": "a".repeat(42) }).to_string(),
            serde_json::json!({ "port": 52111, "state": "st", "challenge": format!("{}/", "a".repeat(42)) })
                .to_string(),
            serde_json::json!({ "port": 52111, "state": "", "challenge": test_challenge() }).to_string(),
            serde_json::json!({ "port": 52111, "state": "s".repeat(257), "challenge": test_challenge() }).to_string(),
            "not json".to_string(),
        ];
        for body in bad_bodies {
            let response = post_consent(&router, body.clone(), Some(&token), &SAME_ORIGIN_JSON).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
        }
    }

    #[tokio::test]
    async fn consent_returns_a_pinned_loopback_redirect_with_a_single_use_code() {
        let manager = Arc::new(SessionManager::new());
        let token = manager
            .create_session("alice".to_string(), "user-1".to_string())
            .await;
        let router = cli_login_router(manager);

        let response = post_consent(&router, consent_body(52111), Some(&token), &SAME_ORIGIN_JSON).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap(),
            "no-store"
        );
        let redirect = consent_redirect_url(response).await;
        assert!(redirect.starts_with("http://127.0.0.1:52111/callback?code="), "{redirect}");
        assert!(redirect.ends_with(&format!("&state={}", "s".repeat(43))));

        let code = code_from_redirect(&redirect);
        assert_eq!(
            post_exchange(&router, &code, TEST_VERIFIER)
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            post_exchange(&router, &code, TEST_VERIFIER)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn exchange_rejects_a_code_that_is_not_36_characters() {
        let router = cli_login_router(Arc::new(SessionManager::new()));
        let response = post_exchange(&router, "short", TEST_VERIFIER).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn exchange_rejects_an_invalid_verifier_before_redeeming() {
        let manager = Arc::new(SessionManager::new());
        let token = manager
            .create_session("alice".to_string(), "user-1".to_string())
            .await;
        let router = cli_login_router(manager);
        let response = post_consent(&router, consent_body(52111), Some(&token), &SAME_ORIGIN_JSON).await;
        let code = code_from_redirect(&consent_redirect_url(response).await);

        let bad = post_exchange(&router, &code, "too-short").await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

        // The malformed attempt did not burn the code.
        let good = post_exchange(&router, &code, TEST_VERIFIER).await;
        assert_eq!(good.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn login_flow_through_mounted_routes() {
        let manager = Arc::new(SessionManager::new());
        let token = manager
            .create_session("alice".to_string(), "user-1".to_string())
            .await;
        let router = cli_login_router(manager);

        let bounce = get_authorize(&router, 52111, None).await;
        assert!(
            bounce
                .status()
                .is_redirection()
        );
        assert_eq!(
            bounce
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap(),
            "no-store"
        );
        let bounce_location = location(&bounce);
        let next = bounce_location
            .strip_prefix("/login?next=")
            .unwrap();
        let decoded = urlencoding::decode(next).unwrap();
        assert_eq!(
            decoded,
            format!("/api/auth/cli/authorize?port=52111&state={}&challenge={}", "s".repeat(43), test_challenge())
        );

        let consent_page = get_authorize(&router, 52111, Some(&token)).await;
        assert_eq!(
            consent_page
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap(),
            "no-store"
        );
        assert_eq!(
            location(&consent_page),
            format!("/cli-consent?port=52111&state={}&challenge={}", "s".repeat(43), test_challenge())
        );

        let granted = post_consent(&router, consent_body(52111), Some(&token), &SAME_ORIGIN_JSON).await;
        assert_eq!(
            granted
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap(),
            "no-store"
        );
        let redirect = consent_redirect_url(granted).await;
        let prefix = "http://127.0.0.1:52111/callback?code=";
        assert!(redirect.starts_with(prefix), "{redirect}");
        assert!(redirect.ends_with(&format!("&state={}", "s".repeat(43))));
        let code = code_from_redirect(&redirect);

        let first = post_exchange(&router, &code, TEST_VERIFIER).await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(
            first
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap(),
            "no-store"
        );
        assert_eq!(
            first
                .headers()
                .get(header::PRAGMA)
                .unwrap(),
            "no-cache"
        );
        let body = first
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["session_token"], token.as_str());

        let second = post_exchange(&router, &code, TEST_VERIFIER).await;
        assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    }
}
