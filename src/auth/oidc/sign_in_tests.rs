//! The real `/oidc/login`, `/oidc/initiate` and `/oidc/callback` handlers against a stub OpenID
//! provider on a loopback port, from the redirect to the provider through the code exchange, the ID
//! token check, the role mapping and the session handed to the dashboard. [`Flow`] serves the routes
//! the identity router mounts in OIDC mode, the logout routes included, for `logout_tests`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::config::TokenEndpointAuthMethod;
use super::egress::ProviderEgress;
use super::test_support::{
    CLIENT_ID, CLIENT_SECRET, KEY_A_KID, KEY_A_PEM, KEY_B_KID, KEY_B_PEM, REDIRECT_URI, StubProvider, config_for,
    id_token_claims, logout_claims, sign, sign_logout_with,
};
use super::throttle::{MAX_FAILED_SIGN_INS, SIGN_IN_REQUESTS_PER_WINDOW};
use super::{OidcConfig, OidcState};
use crate::auth::session::SessionManager;
use crate::auth::storage::{OidcIdentity, PasskeyStorage, UserData};
use crate::auth::types::{UserRole, UserStatus};
use crate::source_auth::client_ip::ClientIp;

pub(super) struct Flow {
    pub(super) app: Router,
    pub(super) oidc: Arc<OidcState>,
    pub(super) provider: StubProvider,
    _dir: tempfile::TempDir,
}

/// The sign-in a test started: what the provider was sent, and the binding cookie the browser
/// holds.
pub(super) struct Started {
    pub(super) state: String,
    pub(super) nonce: String,
    pub(super) authorization: HashMap<String, String>,
    pub(super) cookie: String,
}

impl Flow {
    pub(super) async fn new() -> Self {
        Self::with_config(|_| {}).await
    }

    pub(super) async fn with_config(adjust: impl FnOnce(&mut OidcConfig)) -> Self {
        Self::with_parts(adjust, Arc::new(SessionManager::new())).await
    }

    /// A flow whose sessions live in `sessions`.
    pub(super) async fn with_parts(
        adjust: impl FnOnce(&mut OidcConfig),
        sessions: Arc<SessionManager>,
    ) -> Self {
        let provider = StubProvider::start().await;
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            PasskeyStorage::new(
                dir.path()
                    .join("users")
                    .to_string_lossy()
                    .into_owned(),
                dir.path()
                    .join("avatars")
                    .to_string_lossy()
                    .into_owned(),
            )
            .await
            .unwrap(),
        );
        let mut config = config_for(&provider.issuer);
        adjust(&mut config);
        let egress = ProviderEgress::allowing(&config.issuer);
        let terms = Arc::new(crate::terms::TermsManager::disabled());
        let oidc = Arc::new(OidcState::with_egress(config, storage, sessions.clone(), terms.clone(), egress));
        let app = crate::identity::router::oidc_auth_routes(oidc.clone(), sessions, terms, None);
        Self { app, oidc, provider, _dir: dir }
    }

    pub(super) async fn get(
        &self,
        uri: &str,
        cookie: Option<&str>,
    ) -> Response<Body> {
        self.get_from(BROWSER, uri, cookie)
            .await
    }

    /// A request from the client at `client`.
    pub(super) async fn get_from(
        &self,
        client: &str,
        uri: &str,
        cookie: Option<&str>,
    ) -> Response<Body> {
        let mut request = Request::builder().uri(uri);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        self.send_from(
            client,
            request
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    /// `request`, sent from the client at `client`.
    pub(super) async fn send_from(
        &self,
        client: &str,
        mut request: Request<Body>,
    ) -> Response<Body> {
        request
            .extensions_mut()
            .insert(ClientIp(client.parse().unwrap()));
        self.app
            .clone()
            .oneshot(request)
            .await
            .unwrap()
    }

    /// A form `POST` from the browser.
    pub(super) async fn post_form(
        &self,
        uri: &str,
        form: &str,
    ) -> Response<Body> {
        self.send_from(
            BROWSER,
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form.to_string()))
                .unwrap(),
        )
        .await
    }

    pub(super) async fn start(&self) -> Started {
        self.start_at("/oidc/login")
            .await
    }

    pub(super) async fn start_at(
        &self,
        uri: &str,
    ) -> Started {
        let response = self.get(uri, None).await;
        self.started(&response)
    }

    /// The sign-in a response from `/oidc/login` or `/oidc/initiate` started.
    pub(super) fn started(
        &self,
        response: &Response<Body>,
    ) -> Started {
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = url::Url::parse(header_value(response, header::LOCATION)).unwrap();
        assert!(
            location
                .as_str()
                .starts_with(&format!("{}/authorize?", self.provider.issuer)),
            "{location}"
        );
        let authorization: HashMap<String, String> = location
            .query_pairs()
            .into_owned()
            .collect();
        let cookie = header_value(response, header::SET_COOKIE)
            .split(';')
            .next()
            .unwrap()
            .to_string();
        Started {
            state: authorization["state"].clone(),
            nonce: authorization["nonce"].clone(),
            cookie,
            authorization,
        }
    }

    /// The provider issues an ID token with `claims` for the next code exchange.
    pub(super) fn issue(
        &self,
        claims: Value,
    ) {
        self.provider
            .answer_token_requests(
                StatusCode::OK,
                json!({ "id_token": self.provider.id_token(claims), "token_type": "Bearer" }),
            );
    }

    /// Start a sign-in, have the provider issue `adjust`ed claims for it, and return the
    /// callback's response.
    pub(super) async fn sign_in(
        &self,
        adjust: impl FnOnce(&mut Value),
    ) -> Response<Body> {
        let started = self.start().await;
        let mut claims = id_token_claims(&self.provider.issuer, &started.nonce);
        adjust(&mut claims);
        self.issue(claims);
        self.callback(&started).await
    }

    pub(super) async fn callback(
        &self,
        started: &Started,
    ) -> Response<Body> {
        self.get(&format!("/oidc/callback?code=the-code&state={}", started.state), Some(&started.cookie))
            .await
    }

    pub(super) async fn user(&self) -> Option<UserData> {
        self.oidc
            .storage
            .load_user_by_oidc_identity(&OidcIdentity {
                issuer: self.provider.issuer.clone(),
                subject: "user-1".to_string(),
            })
            .await
            .unwrap()
    }

    pub(super) async fn other_session(
        &self,
        user: &UserData,
    ) -> String {
        self.oidc
            .session_manager
            .create_session(user.username.clone(), user.user_id.clone())
            .await
    }

    pub(super) async fn session_is_live(
        &self,
        token: &str,
    ) -> bool {
        self.oidc
            .session_manager
            .validate_session(token)
            .await
            .is_some()
    }
}

/// The address the tests' browser connects from.
pub(super) const BROWSER: &str = "192.0.2.10";

pub(super) fn header_value(
    response: &Response<Body>,
    name: header::HeaderName,
) -> &str {
    response
        .headers()
        .get(name)
        .unwrap()
        .to_str()
        .unwrap()
}

fn set_cookies(response: &Response<Body>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .to_string()
        })
        .collect()
}

pub(super) async fn body(response: Response<Body>) -> String {
    String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

/// The session token the hand-off page stores for the dashboard.
pub(super) fn handed_off_token(page: &str) -> String {
    page.split("sessionStorage.setItem('session_token', \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .to_string()
}

/// Where the hand-off page sends the browser.
pub(super) fn handed_off_target(page: &str) -> String {
    page.split("window.location.href = \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .replace("\\u0026", "&")
}

#[tokio::test]
async fn a_new_account_signs_in_and_becomes_a_user_with_its_mapped_role() {
    let flow = Flow::new().await;
    let started = flow.start().await;

    assert_eq!(started.authorization["response_type"], "code");
    assert_eq!(started.authorization["client_id"], CLIENT_ID);
    assert_eq!(started.authorization["redirect_uri"], REDIRECT_URI);
    assert_eq!(started.authorization["scope"], "openid profile");
    assert_eq!(started.authorization["code_challenge_method"], "S256");
    assert_ne!(started.state, started.nonce);
    assert!(
        started
            .cookie
            .starts_with(&format!("__Host-oidc_state={}", started.state)),
        "{}",
        started.cookie
    );

    flow.issue(id_token_claims(&flow.provider.issuer, &started.nonce));
    let response = flow.callback(&started).await;

    assert_eq!(response.status(), StatusCode::OK, "the callback answers with the hand-off page, not a redirect");
    assert_eq!(header_value(&response, header::CACHE_CONTROL), "no-store");
    assert_eq!(header_value(&response, header::REFERRER_POLICY), "no-referrer");
    assert!(header_value(&response, header::CONTENT_SECURITY_POLICY).contains("script-src 'nonce-"));
    let cookies = set_cookies(&response);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("__Host-session_token=")),
        "{cookies:?}"
    );
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("__Host-oidc_state=;")),
        "the binding cookie is cleared: {cookies:?}"
    );
    let page = body(response).await;
    assert_eq!(handed_off_target(&page), "/", "without next the browser lands on the dashboard root");
    assert!(
        flow.session_is_live(&handed_off_token(&page))
            .await
    );

    let user = flow.user().await.unwrap();
    assert_eq!(user.username, "alice");
    assert_eq!(user.role, UserRole::Administrator);
    assert_eq!(user.status, UserStatus::Approved);
    assert!(!user.is_primary, "the first OIDC user is not the primary administrator");

    let requests = flow.provider.token_requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.form["grant_type"], "authorization_code");
    assert_eq!(request.form["code"], "the-code");
    assert_eq!(request.form["redirect_uri"], REDIRECT_URI);
    assert_eq!(
        crate::delegation_vault::oauth::generate_pkce_challenge(&request.form["code_verifier"]),
        started.authorization["code_challenge"],
        "the verifier matches the challenge sent to the provider"
    );
    assert_eq!(
        request
            .authorization
            .as_deref(),
        Some(
            format!(
                "Basic {}",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    format!("{CLIENT_ID}:{CLIENT_SECRET}")
                )
            )
            .as_str()
        )
    );
    assert!(
        !request
            .form
            .contains_key("client_secret"),
        "basic authentication keeps the secret out of the form"
    );
}

#[tokio::test]
async fn an_allowed_next_is_where_the_browser_lands_and_any_other_lands_on_the_root() {
    let flow = Flow::new().await;
    let cli = "/api/auth/cli/authorize?port=52111&state=st&challenge=ch";

    for (next, expected) in [(cli, cli), ("/settings", "/"), ("https://evil.example", "/"), ("//evil.example", "/")] {
        let started = flow
            .start_at(&format!("/oidc/login?next={}", urlencoding::encode(next)))
            .await;
        flow.issue(id_token_claims(&flow.provider.issuer, &started.nonce));

        let page = body(flow.callback(&started).await).await;

        assert_eq!(handed_off_target(&page), expected, "next={next}");
    }
}

#[tokio::test]
async fn client_secret_post_sends_the_credentials_in_the_form() {
    let flow =
        Flow::with_config(|config| config.token_endpoint_auth_method = TokenEndpointAuthMethod::ClientSecretPost).await;

    let response = flow.sign_in(|_| {}).await;

    assert_eq!(response.status(), StatusCode::OK);
    let request = &flow.provider.token_requests()[0];
    assert_eq!(request.authorization, None);
    assert_eq!(request.form["client_id"], CLIENT_ID);
    assert_eq!(request.form["client_secret"], CLIENT_SECRET);
}

#[tokio::test]
async fn a_state_works_once() {
    let flow = Flow::new().await;
    let started = flow.start().await;
    flow.issue(id_token_claims(&flow.provider.issuer, &started.nonce));
    assert_eq!(
        flow.callback(&started)
            .await
            .status(),
        StatusCode::OK
    );

    let replayed = flow.callback(&started).await;

    assert_eq!(replayed.status(), StatusCode::BAD_REQUEST);
    assert!(
        body(replayed)
            .await
            .contains("Start again from the sign-in page")
    );
    assert_eq!(
        flow.provider
            .token_requests()
            .len(),
        1,
        "the replayed code is not exchanged"
    );
}

#[tokio::test]
async fn a_callback_without_this_browsers_binding_cookie_is_refused() {
    let flow = Flow::new().await;
    let other = flow.start().await;

    for cookie in [None, Some(other.cookie.as_str()), Some("__Host-oidc_state=forged")] {
        let restarted = flow.start().await;
        let response = flow
            .get(&format!("/oidc/callback?code=the-code&state={}", restarted.state), cookie)
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{cookie:?}");
    }
    assert!(
        flow.provider
            .token_requests()
            .is_empty(),
        "no code is exchanged for an unbound callback"
    );
    assert!(flow.user().await.is_none());
}

#[tokio::test]
async fn an_unbound_callback_leaves_the_sign_in_waiting() {
    let flow = Flow::new().await;
    let started = flow.start().await;

    let foreign = flow
        .get(&format!("/oidc/callback?code=the-code&state={}", started.state), None)
        .await;
    assert_eq!(foreign.status(), StatusCode::BAD_REQUEST);

    flow.issue(id_token_claims(&flow.provider.issuer, &started.nonce));
    assert_eq!(
        flow.callback(&started)
            .await
            .status(),
        StatusCode::OK,
        "the browser that started the sign-in can still finish it"
    );
}

#[tokio::test]
async fn in_one_browser_the_most_recently_started_sign_in_finishes() {
    let flow = Flow::new().await;
    let earlier = flow.start().await;
    let later = flow.start().await;

    let stale = flow
        .get(&format!("/oidc/callback?code=the-code&state={}", earlier.state), Some(&later.cookie))
        .await;
    assert_eq!(stale.status(), StatusCode::BAD_REQUEST);
    assert!(
        set_cookies(&stale)
            .iter()
            .all(|cookie| !cookie.starts_with("__Host-oidc_state=")),
        "the newer sign-in's cookie is left in place"
    );

    flow.issue(id_token_claims(&flow.provider.issuer, &later.nonce));
    assert_eq!(
        flow.callback(&later)
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_provider_refusing_the_sign_in_is_shown_as_such() {
    let flow = Flow::new().await;
    let started = flow.start().await;

    let response = flow
        .get(
            &format!("/oidc/callback?error=access_denied&error_description=%3Cscript%3E&state={}", started.state),
            Some(&started.cookie),
        )
        .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let page = body(response).await;
    assert!(page.contains("did not complete the sign-in"), "{page}");
    assert!(!page.contains("script"), "the provider's description is never echoed: {page}");
}

#[tokio::test]
async fn a_failed_code_exchange_is_refused() {
    let flow = Flow::new().await;
    let started = flow.start().await;
    flow.provider
        .answer_token_requests(StatusCode::BAD_REQUEST, json!({ "error": "invalid_grant" }));

    let response = flow.callback(&started).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(flow.user().await.is_none());
    flow.start().await;
    assert_eq!(
        flow.provider
            .discovery_fetches(),
        1,
        "an OAuth error keeps the discovery document"
    );
}

#[tokio::test]
async fn a_token_endpoint_that_is_gone_has_the_discovery_document_fetched_again() {
    for status in [StatusCode::NOT_FOUND, StatusCode::BAD_GATEWAY] {
        let flow = Flow::new().await;
        let started = flow.start().await;
        flow.provider
            .answer_token_requests(status, json!({}));

        let response = flow.callback(&started).await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{status}");
        flow.start().await;
        assert_eq!(
            flow.provider
                .discovery_fetches(),
            2,
            "{status}"
        );
    }
}

#[tokio::test]
async fn an_id_token_for_another_sign_in_is_refused() {
    let flow = Flow::new().await;

    let response = flow
        .sign_in(|claims| claims["nonce"] = json!("another-sign-ins-nonce"))
        .await;

    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "the provider's token did not verify, which the caller cannot cause"
    );
    assert!(flow.user().await.is_none());
}

#[tokio::test]
async fn an_id_token_from_another_issuer_or_for_another_client_is_refused() {
    for (claim, value) in [("iss", json!("https://other.example")), ("aud", json!("another-client"))] {
        let flow = Flow::new().await;

        let response = flow
            .sign_in(|claims| claims[claim] = value.clone())
            .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{claim}");
        assert!(flow.user().await.is_none(), "{claim}");
    }
}

#[tokio::test]
async fn a_token_endpoint_refusing_this_client_is_a_server_fault() {
    let flow = Flow::new().await;
    let started = flow.start().await;
    flow.provider
        .answer_token_requests(StatusCode::UNAUTHORIZED, json!({ "error": "invalid_client" }));

    let response = flow.callback(&started).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn a_callback_without_a_code_is_a_bad_request() {
    let flow = Flow::new().await;
    let started = flow.start().await;

    let response = flow
        .get(&format!("/oidc/callback?state={}", started.state), Some(&started.cookie))
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        flow.provider
            .token_requests()
            .is_empty()
    );
}

#[tokio::test]
async fn an_account_of_another_tenant_is_refused_before_any_user_is_created() {
    let flow = Flow::new().await;

    let response = flow
        .sign_in(|claims| claims["org_id"] = json!("org_999"))
        .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        body(response)
            .await
            .contains("not allowed to use this dashboard")
    );
    assert!(flow.user().await.is_none());
}

#[tokio::test]
async fn the_tenant_value_may_come_inside_an_array() {
    let flow = Flow::new().await;

    let response = flow
        .sign_in(|claims| claims["org_id"] = json!(["org_9", "org_123"]))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn an_account_whose_role_was_removed_upstream_is_refused_and_signed_out_everywhere() {
    let flow = Flow::new().await;
    assert_eq!(
        flow.sign_in(|_| {})
            .await
            .status(),
        StatusCode::OK
    );
    let user = flow.user().await.unwrap();
    let elsewhere = flow
        .other_session(&user)
        .await;

    let response = flow
        .sign_in(|claims| claims["roles"] = json!(["guest"]))
        .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        !flow
            .session_is_live(&elsewhere)
            .await,
        "the user's other sessions ended"
    );
    let stored = flow.user().await.unwrap();
    assert_eq!(stored.status, UserStatus::Approved, "the record is kept");
    assert_eq!(stored.role, UserRole::Administrator, "a refused sign-in changes nothing stored");
}

#[tokio::test]
async fn a_role_named_like_a_gateway_role_but_not_mapped_is_refused() {
    for roles in [json!("administrator"), json!(["Admin"]), json!([])] {
        let flow = Flow::new().await;

        let response = flow
            .sign_in(|claims| claims["roles"] = roles.clone())
            .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{roles}");
        assert!(flow.user().await.is_none(), "{roles}");
    }
}

#[tokio::test]
async fn an_unmapped_account_gets_the_unmapped_role_when_one_is_set() {
    let flow = Flow::with_config(|config| config.role_mapping.unmapped = Some(UserRole::User)).await;

    let response = flow
        .sign_in(|claims| {
            claims
                .as_object_mut()
                .unwrap()
                .remove("roles");
        })
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        flow.user()
            .await
            .unwrap()
            .role,
        UserRole::User
    );
}

#[tokio::test]
async fn a_changed_role_takes_effect_and_ends_other_sessions_while_an_unchanged_one_keeps_them() {
    let flow = Flow::new().await;
    flow.sign_in(|_| {}).await;
    let user = flow.user().await.unwrap();
    let elsewhere = flow
        .other_session(&user)
        .await;

    flow.sign_in(|_| {}).await;
    assert!(
        flow.session_is_live(&elsewhere)
            .await,
        "same role: other sessions continue"
    );

    let response = flow
        .sign_in(|claims| claims["roles"] = json!("member"))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        flow.user()
            .await
            .unwrap()
            .role,
        UserRole::User
    );
    assert!(
        !flow
            .session_is_live(&elsewhere)
            .await,
        "a demotion ends the user's other sessions"
    );
    assert!(
        flow.session_is_live(&handed_off_token(&body(response).await))
            .await,
        "the session of the sign-in that demoted the user is kept"
    );
}

#[tokio::test]
async fn a_user_who_is_not_approved_is_refused_even_with_a_valid_token_and_signed_out_everywhere() {
    for status in [UserStatus::Disabled, UserStatus::New] {
        let flow = Flow::new().await;
        flow.sign_in(|_| {}).await;
        let mut user = flow.user().await.unwrap();
        let elsewhere = flow
            .other_session(&user)
            .await;
        user.status = status.clone();
        flow.oidc
            .storage
            .save_user(&user)
            .await
            .unwrap();

        let response = flow.sign_in(|_| {}).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{status}");
        assert!(
            !flow
                .session_is_live(&elsewhere)
                .await,
            "{status}: the user's other sessions ended"
        );
    }
}

impl Flow {
    async fn administrator(&self) -> UserData {
        let now = chrono::Utc::now();
        let admin = UserData {
            user_id: "admin-1".to_string(),
            username: "admin".to_string(),
            passkeys: Vec::new(),
            role: UserRole::Administrator,
            status: UserStatus::Approved,
            is_primary: true,
            first_name: None,
            last_name: None,
            email: None,
            department: None,
            job_title: None,
            avatar_path: None,
            created_at: now,
            updated_at: now,
            last_logged_in: None,
            saml_id: None,
            oidc: None,
            deleted_at: None,
        };
        self.oidc
            .storage
            .save_user(&admin)
            .await
            .unwrap();
        admin
    }

    /// `request` through the real user management routes, sent by `caller`.
    async fn as_administrator(
        &self,
        caller: &UserData,
        request: Request<Body>,
    ) -> (StatusCode, Value) {
        let response = crate::auth_manager::handlers::user_routes_for_tests(
            self.oidc.storage.clone(),
            self.oidc
                .session_manager
                .clone(),
            None,
            &caller.user_id,
        )
        .oneshot(request)
        .await
        .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn delete_user(
        &self,
        caller: &UserData,
        user_id: &str,
    ) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/users/{user_id}"))
            .body(Body::empty())
            .unwrap();
        self.as_administrator(caller, request)
            .await
    }

    async fn approve_user(
        &self,
        caller: &UserData,
        user_id: &str,
    ) -> StatusCode {
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/v1/users/{user_id}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "status": "approved" }).to_string()))
            .unwrap();
        self.as_administrator(caller, request)
            .await
            .0
    }

    async fn stored_user_count(&self) -> usize {
        self.oidc
            .storage
            .list_users()
            .await
            .unwrap()
            .len()
    }
}

#[tokio::test]
async fn a_deleted_user_is_refused_at_the_next_sign_in_and_not_created_again() {
    let flow = Flow::new().await;
    let admin = flow.administrator().await;
    flow.sign_in(|claims| claims["roles"] = json!(["member"]))
        .await;
    let user = flow.user().await.unwrap();
    let elsewhere = flow
        .other_session(&user)
        .await;

    let (deleted, answer) = flow
        .delete_user(&admin, &user.user_id)
        .await;
    let response = flow
        .sign_in(|claims| claims["roles"] = json!(["member"]))
        .await;

    assert_eq!((deleted, answer), (StatusCode::OK, json!({ "outcome": "disabled" })));
    assert!(
        !flow
            .session_is_live(&elsewhere)
            .await,
        "deleting the user ended their sessions"
    );
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        set_cookies(&response)
            .iter()
            .all(|cookie| !cookie.starts_with("__Host-session_token=")),
        "the refused sign-in opens no session"
    );
    let kept = flow.user().await.unwrap();
    assert_eq!(kept.user_id, user.user_id, "no second user was created");
    assert_eq!(kept.status, UserStatus::Disabled);
    assert!(kept.deleted_at.is_some());
    assert_eq!(flow.stored_user_count().await, 2);
}

#[tokio::test]
async fn a_deleted_user_signs_in_as_the_same_user_once_an_administrator_approves_them_again() {
    let flow = Flow::new().await;
    let admin = flow.administrator().await;
    flow.sign_in(|claims| claims["roles"] = json!(["member"]))
        .await;
    let user = flow.user().await.unwrap();
    flow.delete_user(&admin, &user.user_id)
        .await;

    let approved = flow
        .approve_user(&admin, &user.user_id)
        .await;
    let response = flow.sign_in(|_| {}).await;

    assert_eq!(approved, StatusCode::OK);
    assert_eq!(response.status(), StatusCode::OK);
    let back = flow.user().await.unwrap();
    assert_eq!(back.user_id, user.user_id);
    assert_eq!(
        (back.status, back.role),
        (UserStatus::Approved, UserRole::Administrator),
        "the role comes from the ID token"
    );
    assert_eq!(back.username, "alice", "the next sign-in gives the record its username again");
    assert!(back.deleted_at.is_none());
    assert_eq!(flow.stored_user_count().await, 2);
}

#[tokio::test]
async fn an_id_token_that_expired_within_the_clock_skew_leeway_signs_in() {
    let flow = Flow::new().await;

    let page = flow
        .sign_in(|claims| claims["exp"] = json!(chrono::Utc::now().timestamp() - 30))
        .await;

    assert_eq!(page.status(), StatusCode::OK);
    assert!(flow.user().await.is_some());
}

#[tokio::test]
async fn an_id_token_signed_with_a_key_published_during_the_unknown_key_cooldown_is_refused_as_unavailable() {
    let _ready = crate::server::mode::ready_for_test().await;
    let flow = Flow::new().await;
    for (kid, status) in [(KEY_A_KID, StatusCode::OK), ("made-up", StatusCode::BAD_REQUEST)] {
        let logout = sign_logout_with(KEY_A_PEM, Some(kid), &logout_claims(&flow.provider.issuer, "op-session-1"));
        let response = flow
            .post_form("/oidc/backchannel-logout", &format!("logout_token={logout}"))
            .await;
        assert_eq!(response.status(), status, "{kid}");
    }
    flow.provider
        .rotate_to_key_b();
    let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();

    let started = flow.start().await;
    flow.provider
        .answer_token_requests(
            StatusCode::OK,
            json!({
                "id_token": sign(KEY_B_PEM, Some(KEY_B_KID), &id_token_claims(&flow.provider.issuer, &started.nonce)),
                "token_type": "Bearer",
            }),
        );
    let page = flow.callback(&started).await;

    assert_eq!(page.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body(page)
            .await
            .contains("Sign-in unavailable")
    );
    assert!(flow.user().await.is_none());
    let text = logs.text();
    assert!(text.contains("op_unavailable"), "{text}");
    assert!(!text.contains("id_token_invalid"), "{text}");
}

#[tokio::test]
async fn an_unreachable_provider_shows_a_readable_page() {
    let flow = Flow::with_config(|config| config.issuer = "http://127.0.0.1:9".to_string()).await;

    let response = flow
        .get("/oidc/login", None)
        .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body(response)
            .await
            .contains("OpenID provider could not be reached")
    );
}

#[tokio::test]
async fn a_client_over_its_sign_in_budget_is_told_when_to_retry() {
    let flow = Flow::new().await;
    for _ in 0..SIGN_IN_REQUESTS_PER_WINDOW {
        flow.start().await;
    }

    let throttled = flow
        .get("/oidc/login", None)
        .await;

    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = header_value(&throttled, header::RETRY_AFTER)
        .parse()
        .unwrap();
    assert!(retry_after > 0 && retry_after <= 60, "rate limited, not locked out: {retry_after}");
    assert_eq!(header_value(&throttled, header::CACHE_CONTROL), "no-store");
    assert_eq!(
        flow.provider
            .discovery_fetches(),
        1,
        "a throttled start reaches nothing"
    );
    assert_eq!(
        flow.get_from("192.0.2.11", "/oidc/login", None)
            .await
            .status(),
        StatusCode::SEE_OTHER,
        "another client has its own budget"
    );
}

#[tokio::test]
async fn repeated_refused_codes_lock_the_client_out_while_unbound_callbacks_do_not() {
    let flow = Flow::new().await;
    let guesser = "192.0.2.21";
    for _ in 0..MAX_FAILED_SIGN_INS {
        let started = flow.start().await;
        let refused = flow
            .get_from(guesser, &format!("/oidc/callback?code=a-guess&state={}", started.state), Some(&started.cookie))
            .await;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED, "the provider refuses the code");
    }

    let locked = flow
        .get_from(guesser, "/oidc/login", None)
        .await;

    assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = header_value(&locked, header::RETRY_AFTER)
        .parse()
        .unwrap();
    assert!(retry_after > 60, "locked out for longer than a window: {retry_after}");

    let unbound = "192.0.2.22";
    for _ in 0..SIGN_IN_REQUESTS_PER_WINDOW {
        assert_eq!(
            flow.get_from(unbound, "/oidc/callback?code=c&state=unknown", None)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let limited = flow
        .get_from(unbound, "/oidc/callback?code=c&state=unknown", None)
        .await;
    let retry_after: u64 = header_value(&limited, header::RETRY_AFTER)
        .parse()
        .unwrap();
    assert!(retry_after <= 60, "an unbound callback is not a failed sign-in: {retry_after}");
}

#[tokio::test]
async fn an_existing_user_outside_the_tenant_binding_is_refused_and_signed_out_everywhere() {
    let flow = Flow::new().await;
    assert_eq!(
        flow.sign_in(|_| {})
            .await
            .status(),
        StatusCode::OK
    );
    let user = flow.user().await.unwrap();
    let elsewhere = flow
        .other_session(&user)
        .await;

    let response = flow
        .sign_in(|claims| claims["org_id"] = json!("org_999"))
        .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        set_cookies(&response)
            .iter()
            .all(|cookie| !cookie.starts_with("__Host-session_token=")),
        "no session is opened"
    );
    assert!(
        !flow
            .session_is_live(&elsewhere)
            .await,
        "the user's other sessions ended"
    );
    let stored = flow.user().await.unwrap();
    assert_eq!(stored.status, UserStatus::Approved, "the record is kept");
    assert_eq!(stored.role, UserRole::Administrator, "a refused sign-in changes nothing stored");
}

#[tokio::test]
async fn a_refusal_is_an_uncached_page_that_clears_the_binding_cookie() {
    let flow = Flow::new().await;

    let refused = flow
        .sign_in(|claims| claims["roles"] = json!(["guest"]))
        .await;

    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(header_value(&refused, header::CACHE_CONTROL), "no-store");
    assert!(header_value(&refused, header::CONTENT_TYPE).starts_with("text/html"));
    assert!(
        set_cookies(&refused)
            .iter()
            .any(|cookie| cookie.starts_with("__Host-oidc_state=;")),
        "{:?}",
        set_cookies(&refused)
    );

    let started = flow
        .get("/oidc/login", None)
        .await;
    assert_eq!(header_value(&started, header::CACHE_CONTROL), "no-store");
}

#[tokio::test]
async fn no_secret_code_or_token_reaches_the_log() {
    let flow = Flow::new().await;
    let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();

    let page = body(flow.sign_in(|_| {}).await).await;
    let session_token = handed_off_token(&page);
    let issued = flow.provider.token_requests();
    let started = flow.start().await;
    flow.provider
        .answer_token_requests(StatusCode::BAD_REQUEST, json!({ "error": "invalid_grant" }));
    assert_eq!(
        flow.callback(&started)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let text = logs.text();
    assert!(text.contains("OIDC sign-in succeeded"), "the flow was logged: {text}");
    assert!(text.contains("exchange_failed"), "{text}");
    for secret in [
        CLIENT_SECRET,
        "the-code",
        session_token.as_str(),
        issued[0].form["code_verifier"].as_str(),
        started.nonce.as_str(),
        "alice@example.com",
        "org_123",
    ] {
        assert!(!text.contains(secret), "{secret} reached the log: {text}");
    }
}

impl Flow {
    /// The query string that names this provider as `iss`, with `rest` after it.
    fn initiate_query(
        &self,
        rest: &str,
    ) -> String {
        format!("iss={}{rest}", urlencoding::encode(&self.provider.issuer))
    }
}

#[tokio::test]
async fn the_providers_link_starts_a_fresh_sign_in_by_get_or_post_with_its_login_hint() {
    let flow = Flow::new().await;

    let by_get = flow
        .get(&format!("/oidc/initiate?{}", flow.initiate_query("&login_hint=alice%40example.com")), None)
        .await;
    let by_post = flow
        .post_form("/oidc/initiate", &flow.initiate_query("&login_hint=bob%40example.com"))
        .await;

    let by_get = flow.started(&by_get);
    let by_post = flow.started(&by_post);
    assert_eq!(by_get.authorization["login_hint"], "alice@example.com");
    assert_eq!(by_post.authorization["login_hint"], "bob@example.com");
    assert_eq!(by_post.authorization["code_challenge_method"], "S256");
    assert!(
        by_post
            .cookie
            .starts_with(&format!("__Host-oidc_state={}", by_post.state)),
        "{}",
        by_post.cookie
    );
    assert_ne!(by_get.state, by_post.state, "every link starts its own sign-in");
}

#[tokio::test]
async fn a_login_hint_that_is_too_long_or_holds_a_control_character_is_dropped() {
    let flow = Flow::new().await;

    for hint in ["a%0Ab".to_string(), "a".repeat(257)] {
        let started = flow.started(
            &flow
                .get(&format!("/oidc/initiate?{}", flow.initiate_query(&format!("&login_hint={hint}"))), None)
                .await,
        );
        assert!(
            !started
                .authorization
                .contains_key("login_hint"),
            "{hint}"
        );
    }
}

#[tokio::test]
async fn a_link_for_another_provider_or_without_one_is_refused() {
    let flow = Flow::new().await;

    for uri in ["/oidc/initiate?iss=https%3A%2F%2Fother.example", "/oidc/initiate", "/oidc/initiate?iss="] {
        let response = flow.get(uri, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(header_value(&response, header::CACHE_CONTROL), "no-store", "{uri}");
        assert!(
            body(response)
                .await
                .contains("This sign-in link is not for this dashboard."),
            "{uri}"
        );
    }
    let issuer_with_slash = format!("iss={}", urlencoding::encode(&format!("{}/", flow.provider.issuer)));
    let response = flow
        .post_form("/oidc/initiate", &issuer_with_slash)
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "the issuer must match exactly");
    assert_eq!(
        flow.provider
            .discovery_fetches(),
        0,
        "iss is never used to fetch anything"
    );
}

#[tokio::test]
async fn the_dashboard_opens_at_an_allowed_target_on_its_own_origin_and_nowhere_else() {
    let flow = Flow::new().await;
    for (target, expected) in [
        ("https://gateway.example.com/access-tokens/new?name=CI", "/access-tokens/new?name=CI"),
        ("https://evil.example/access-tokens/new", "/"),
        ("https://gateway.example.com//evil.example/", "/"),
        ("/access-tokens/new", "/"),
    ] {
        let started = flow.started(
            &flow
                .get(
                    &format!(
                        "/oidc/initiate?{}",
                        flow.initiate_query(&format!("&target_link_uri={}", urlencoding::encode(target)))
                    ),
                    None,
                )
                .await,
        );
        flow.issue(id_token_claims(&flow.provider.issuer, &started.nonce));

        let page = flow.callback(&started).await;

        assert_eq!(page.status(), StatusCode::OK, "{target}");
        assert_eq!(handed_off_target(&body(page).await), expected, "{target}");
    }
}

#[tokio::test]
async fn a_link_spends_the_sign_in_budget_it_shares_with_the_login_page() {
    let flow = Flow::new().await;
    for _ in 0..SIGN_IN_REQUESTS_PER_WINDOW / 2 {
        flow.start().await;
        flow.started(
            &flow
                .get(&format!("/oidc/initiate?{}", flow.initiate_query("")), None)
                .await,
        );
    }

    let by_get = flow
        .get(&format!("/oidc/initiate?{}", flow.initiate_query("")), None)
        .await;
    let by_post = flow
        .post_form("/oidc/initiate", &flow.initiate_query(""))
        .await;
    let login = flow
        .get("/oidc/login", None)
        .await;

    for throttled in [by_get, by_post, login] {
        assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            throttled
                .headers()
                .contains_key(header::RETRY_AFTER)
        );
    }
    assert_eq!(
        flow.get_from("192.0.2.31", &format!("/oidc/initiate?{}", flow.initiate_query("")), None)
            .await
            .status(),
        StatusCode::SEE_OTHER,
        "another client has its own budget"
    );
}

#[tokio::test]
async fn a_link_posted_cross_site_neither_reads_nor_ends_the_browsers_session() {
    let flow = Flow::new().await;
    let page = flow.sign_in(|_| {}).await;
    let session = handed_off_token(&body(page).await);

    let response = flow
        .send_from(
            BROWSER,
            Request::builder()
                .method("POST")
                .uri("/oidc/initiate")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, &flow.provider.issuer)
                .header("sec-fetch-site", "cross-site")
                .header(header::COOKIE, format!("__Host-session_token={session}"))
                .header(header::AUTHORIZATION, format!("Bearer {session}"))
                .body(Body::from(flow.initiate_query("")))
                .unwrap(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookies = set_cookies(&response);
    assert_eq!(cookies.len(), 1, "{cookies:?}");
    assert!(cookies[0].starts_with("__Host-oidc_state="), "only the new sign-in's binding cookie: {cookies:?}");
    assert!(
        flow.session_is_live(&session)
            .await
    );
}

#[tokio::test]
async fn in_oidc_mode_only_sessions_from_a_sign_in_at_this_provider_are_accepted() {
    let sessions = Arc::new(SessionManager::new());
    let flow = Flow::with_parts(|_| {}, sessions.clone()).await;
    let from_passkey_sign_in = sessions
        .create_session("admin".into(), "user-admin".into())
        .await;
    let from_another_provider = sessions
        .create_session_with_terms_gate(
            "carol".into(),
            "user-carol".into(),
            crate::auth::session::TermsSessionGate::AllowedAtLogin,
            Some(crate::auth::session::OidcSessionBinding {
                issuer: "https://idp.other.example".into(),
                subject: "carol".into(),
                sid: None,
                id_token: None,
            }),
        )
        .await;

    sessions.accept_only_sign_ins_at(&flow.provider.issuer);
    let from_this_provider = handed_off_token(&body(flow.sign_in(|_| {}).await).await);

    assert!(
        sessions
            .validate_session(&from_this_provider)
            .await
            .is_some()
    );
    assert!(
        sessions
            .is_live(&from_this_provider)
            .await
    );
    for refused in [&from_passkey_sign_in, &from_another_provider] {
        assert!(
            sessions
                .validate_session(refused)
                .await
                .is_none()
        );
        assert!(
            !sessions
                .is_live(refused)
                .await
        );
    }
}
