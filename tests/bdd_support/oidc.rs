//! A local OpenID provider for real-process scenarios. It signs the caller's
//! identity token, serves the authorization and token endpoints of the
//! authorization-code flow with S256 PKCE, and answers a code with an access,
//! refresh and ID token for the subject signed in at the provider. Its token
//! endpoint also grants the gateway its own access token for client credentials.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use axum::extract::{Form, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use url::Url;

use crate::bdd_support::jwt::{now_secs, public_jwk, sign_jwt};

pub const OIDC_ISSUER: &str = "https://identity.example/";
pub const OIDC_CLIENT_ID: &str = "bdd-oidc-client";
pub const OIDC_CLIENT_SECRET: &str = "bdd-oidc-client-secret";

#[derive(Debug, Clone)]
struct Grant {
    subject: String,
    nonce: String,
    code_challenge: String,
    redirect_uri: String,
}

#[derive(Debug, Default)]
struct ProviderState {
    signed_in: Mutex<Option<String>>,
    grants: Mutex<HashMap<String, Grant>>,
    token_requests: AtomicU64,
    token_endpoint_down: AtomicBool,
    next_code: AtomicU64,
    access_token: String,
    refresh_token: String,
}

pub struct OidcProvider {
    port: u16,
    state: Arc<ProviderState>,
    handle: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for OidcProvider {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("OidcProvider")
            .field("port", &self.port)
            .finish()
    }
}

impl Drop for OidcProvider {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl OidcProvider {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let state = Arc::new(ProviderState {
            access_token: format!("bdd-delegated-access-{}", uuid::Uuid::new_v4()),
            refresh_token: format!("bdd-delegated-refresh-{}", uuid::Uuid::new_v4()),
            ..ProviderState::default()
        });
        let app = Router::new()
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .with_state(state.clone());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        Self {
            port: addr.port(),
            state,
            handle,
        }
    }

    /// The authorization endpoint a gateway sends the caller to. A gateway
    /// accepts only HTTPS here; [`OidcProvider::local_url`] maps it back to
    /// this plain-HTTP server.
    pub fn authorization_endpoint(&self) -> String {
        format!("https://127.0.0.1:{}/authorize", self.port)
    }

    pub fn token_endpoint(&self) -> String {
        format!("http://127.0.0.1:{}/token", self.port)
    }

    /// Map a URL on [`OidcProvider::authorization_endpoint`] to the address
    /// this server listens on. Any other URL is refused.
    pub fn local_url(
        &self,
        url: &Url,
    ) -> anyhow::Result<Url> {
        let mut endpoint = url.clone();
        endpoint.set_query(None);
        anyhow::ensure!(
            endpoint.as_str() == self.authorization_endpoint(),
            "expected a URL on {}, got {url}",
            self.authorization_endpoint()
        );
        let mut local = url.clone();
        local
            .set_scheme("http")
            .map_err(|()| anyhow::anyhow!("set http scheme on {url}"))?;
        Ok(local)
    }

    pub fn public_jwk(&self) -> serde_json::Value {
        public_jwk()
    }

    /// An identity token the provider issued to `subject`, as a caller
    /// presents it for token exchange.
    pub fn identity_token(
        &self,
        subject: &str,
    ) -> String {
        let now = now_secs();
        sign_jwt(serde_json::json!({
            "iss": OIDC_ISSUER,
            "sub": subject,
            "aud": OIDC_CLIENT_ID,
            "iat": now,
            "exp": now + 600,
        }))
    }

    pub async fn sign_in(
        &self,
        subject: &str,
    ) {
        *self
            .state
            .signed_in
            .lock()
            .await = Some(subject.to_string());
    }

    pub fn access_token(&self) -> &str {
        &self.state.access_token
    }

    pub fn refresh_token(&self) -> &str {
        &self.state.refresh_token
    }

    /// Make the token endpoint answer `503` to every request from now on.
    pub fn take_token_endpoint_down(&self) {
        self.state
            .token_endpoint_down
            .store(true, Ordering::SeqCst);
    }

    pub fn token_request_count(&self) -> u64 {
        self.state
            .token_requests
            .load(Ordering::SeqCst)
    }
}

async fn authorize(
    State(state): State<Arc<ProviderState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let param = |name: &str| {
        params
            .get(name)
            .filter(|value| !value.is_empty())
            .cloned()
    };
    if param("response_type").as_deref() != Some("code")
        || param("client_id").as_deref() != Some(OIDC_CLIENT_ID)
        || param("code_challenge_method").as_deref() != Some("S256")
    {
        return (StatusCode::BAD_REQUEST, "invalid authorization request").into_response();
    }
    let (Some(redirect_uri), Some(request_state), Some(nonce), Some(code_challenge)) =
        (param("redirect_uri"), param("state"), param("nonce"), param("code_challenge"))
    else {
        return (StatusCode::BAD_REQUEST, "incomplete authorization request").into_response();
    };
    let Some(subject) = state
        .signed_in
        .lock()
        .await
        .clone()
    else {
        return (StatusCode::UNAUTHORIZED, "no subject is signed in").into_response();
    };
    let Ok(mut location) = Url::parse(&redirect_uri) else {
        return (StatusCode::BAD_REQUEST, "invalid redirect_uri").into_response();
    };
    let code = format!(
        "bdd-code-{}",
        state
            .next_code
            .fetch_add(1, Ordering::SeqCst)
    );
    state
        .grants
        .lock()
        .await
        .insert(
            code.clone(),
            Grant {
                subject,
                nonce,
                code_challenge,
                redirect_uri,
            },
        );
    location
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &request_state)
        .append_pair("iss", OIDC_ISSUER);
    (StatusCode::FOUND, [(header::LOCATION, location.to_string())]).into_response()
}

async fn token(
    State(state): State<Arc<ProviderState>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    state
        .token_requests
        .fetch_add(1, Ordering::SeqCst);
    if state
        .token_endpoint_down
        .load(Ordering::SeqCst)
    {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "temporarily_unavailable"})))
            .into_response();
    }
    let invalid_grant =
        || (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_grant"}))).into_response();
    let field = |name: &str| {
        form.get(name)
            .map(String::as_str)
    };
    if field("client_id") != Some(OIDC_CLIENT_ID) || field("client_secret") != Some(OIDC_CLIENT_SECRET) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_client"}))).into_response();
    }
    match field("grant_type") {
        Some("authorization_code") => {}
        Some("client_credentials") => {
            return Json(serde_json::json!({
                "access_token": state.access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
            }))
            .into_response();
        }
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "unsupported_grant_type"})))
                .into_response();
        }
    }
    let grant = match field("code") {
        Some(code) => state
            .grants
            .lock()
            .await
            .remove(code),
        None => None,
    };
    let Some(grant) = grant else {
        return invalid_grant();
    };
    let verifier_digest = field("code_verifier").map(|verifier| URL_SAFE_NO_PAD.encode(Sha256::digest(verifier)));
    if verifier_digest.as_deref() != Some(grant.code_challenge.as_str())
        || field("redirect_uri") != Some(grant.redirect_uri.as_str())
    {
        return invalid_grant();
    }
    let now = now_secs();
    let id_token = sign_jwt(serde_json::json!({
        "iss": OIDC_ISSUER,
        "sub": grant.subject,
        "aud": OIDC_CLIENT_ID,
        "nonce": grant.nonce,
        "iat": now,
        "exp": now + 300,
    }));
    Json(serde_json::json!({
        "access_token": state.access_token,
        "refresh_token": state.refresh_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn client_credentials(provider: &OidcProvider) -> reqwest::Response {
        reqwest::Client::new()
            .post(provider.token_endpoint())
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", OIDC_CLIENT_ID),
                ("client_secret", OIDC_CLIENT_SECRET),
            ])
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn client_credentials_grant_returns_the_gateway_access_token_and_counts_the_request() {
        let provider = OidcProvider::start().await;

        let response = client_credentials(&provider).await;

        assert_eq!(response.status(), 200);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["access_token"], provider.access_token());
        assert_eq!(provider.token_request_count(), 1);
    }

    #[tokio::test]
    async fn token_endpoint_answers_503_once_taken_down_and_still_counts_requests() {
        let provider = OidcProvider::start().await;
        provider.take_token_endpoint_down();

        let response = client_credentials(&provider).await;

        assert_eq!(response.status(), 503);
        assert_eq!(provider.token_request_count(), 1);
    }
}
