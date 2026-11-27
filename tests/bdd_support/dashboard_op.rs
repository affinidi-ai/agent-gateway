//! A local OpenID provider that dashboard users sign in at, for real-process scenarios. It serves
//! discovery, its JWKS, an authorization endpoint that signs in whichever person the scenario
//! names, and a token endpoint that answers a code with an EdDSA ID token for that person, after
//! checking the client's Basic credentials, the PKCE verifier and the redirect URI.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use url::Url;

use crate::bdd_support::jwt::{now_secs, public_jwk, sign_jwt};

pub const DASHBOARD_CLIENT_ID: &str = "bdd-dashboard";
pub const DASHBOARD_CLIENT_SECRET: &str = "bdd-dashboard-secret";
/// The provider's name on the sign-in button.
pub const DASHBOARD_PROVIDER_LABEL: &str = "Example Directory";
/// The tenant the gateway's `oidc.json` binds sign-in to.
pub const BOUND_TENANT: &str = "org-bdd";

struct Grant {
    claims: Value,
    nonce: String,
    code_challenge: String,
    redirect_uri: String,
}

#[derive(Default)]
struct ProviderState {
    issuer: String,
    signing_in: Mutex<Option<Value>>,
    grants: Mutex<HashMap<String, Grant>>,
    next_code: Mutex<u64>,
}

/// The provider. It stops when dropped.
pub struct DashboardOp {
    state: Arc<ProviderState>,
    handle: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for DashboardOp {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("DashboardOp")
            .field("issuer", &self.state.issuer)
            .finish()
    }
}

impl Drop for DashboardOp {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl DashboardOp {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the OpenID provider");
        let issuer = format!(
            "http://127.0.0.1:{}",
            listener
                .local_addr()
                .expect("the provider's address")
                .port()
        );
        let state = Arc::new(ProviderState {
            issuer,
            ..ProviderState::default()
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .with_state(state.clone());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve the OpenID provider");
        });
        Self { state, handle }
    }

    pub fn issuer(&self) -> &str {
        &self.state.issuer
    }

    /// The next authorization request signs in the person `subject` with `claims` added to the
    /// standard ones.
    pub async fn sign_in_as(
        &self,
        subject: &str,
        claims: Value,
    ) {
        let mut person = json!({ "sub": subject, "preferred_username": subject });
        for (name, value) in claims
            .as_object()
            .expect("claims are an object")
        {
            person[name] = value.clone();
        }
        *self
            .state
            .signing_in
            .lock()
            .await = Some(person);
    }
}

async fn discovery(State(state): State<Arc<ProviderState>>) -> Json<Value> {
    let issuer = &state.issuer;
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
    }))
}

async fn jwks() -> Json<Value> {
    Json(json!({ "keys": [public_jwk()] }))
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
        || param("client_id").as_deref() != Some(DASHBOARD_CLIENT_ID)
        || param("code_challenge_method").as_deref() != Some("S256")
        || !param("scope").is_some_and(|scope| {
            scope
                .split(' ')
                .any(|scope| scope == "openid")
        })
    {
        return (StatusCode::BAD_REQUEST, "invalid authorization request").into_response();
    }
    let (Some(redirect_uri), Some(request_state), Some(nonce), Some(code_challenge)) =
        (param("redirect_uri"), param("state"), param("nonce"), param("code_challenge"))
    else {
        return (StatusCode::BAD_REQUEST, "incomplete authorization request").into_response();
    };
    let Some(claims) = state
        .signing_in
        .lock()
        .await
        .clone()
    else {
        return (StatusCode::UNAUTHORIZED, "no person is signing in").into_response();
    };
    let Ok(mut location) = Url::parse(&redirect_uri) else {
        return (StatusCode::BAD_REQUEST, "invalid redirect_uri").into_response();
    };
    let code = {
        let mut next = state.next_code.lock().await;
        *next += 1;
        format!("bdd-dashboard-code-{next}")
    };
    state
        .grants
        .lock()
        .await
        .insert(
            code.clone(),
            Grant {
                claims,
                nonce,
                code_challenge,
                redirect_uri,
            },
        );
    location
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &request_state);
    (StatusCode::FOUND, [(header::LOCATION, location.to_string())]).into_response()
}

async fn token(
    State(state): State<Arc<ProviderState>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let expected = format!("Basic {}", STANDARD.encode(format!("{DASHBOARD_CLIENT_ID}:{DASHBOARD_CLIENT_SECRET}")));
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        != Some(expected.as_str())
    {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_client"}))).into_response();
    }
    let field = |name: &str| {
        form.get(name)
            .map(String::as_str)
    };
    let grant = match (field("grant_type"), field("code")) {
        (Some("authorization_code"), Some(code)) => state
            .grants
            .lock()
            .await
            .remove(code),
        _ => None,
    };
    let invalid_grant = || (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant"}))).into_response();
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
    let mut claims = grant.claims;
    for (name, value) in [
        ("iss", json!(state.issuer)),
        ("aud", json!(DASHBOARD_CLIENT_ID)),
        ("nonce", json!(grant.nonce)),
        ("iat", json!(now)),
        ("exp", json!(now + 300)),
    ] {
        claims[name] = value;
    }
    Json(json!({
        "access_token": "bdd-dashboard-access-token",
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": sign_jwt(claims),
    }))
    .into_response()
}
