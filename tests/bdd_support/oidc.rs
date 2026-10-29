//! A local OpenID provider for real-process scenarios. It signs the caller's
//! identity token, serves the authorization and token endpoints of the
//! authorization-code flow with S256 PKCE, and answers a code with an access,
//! refresh and ID token for the subject signed in at the provider. Its token
//! endpoint also grants the gateway its own access token for client credentials,
//! and for an RFC 7523 JWT bearer assertion signed with a key it trusts.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, OnceLock, PoisonError};

use axum::extract::{Form, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use url::Url;

use crate::bdd_support::jwt::{now_secs, public_jwk, sign_jwt};

pub const OIDC_ISSUER: &str = "https://identity.example/";
pub const OIDC_CLIENT_ID: &str = "bdd-oidc-client";
pub const OIDC_CLIENT_SECRET: &str = "bdd-oidc-client-secret";
pub const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Longest assertion lifetime the provider accepts, as a public authorization server allows.
const MAX_ASSERTION_LIFETIME_SECS: u64 = 3600;
/// How far in the future an assertion's `iat` may be.
const MAX_ASSERTION_IAT_SKEW_SECS: u64 = 60;

#[derive(Debug, Clone)]
struct Grant {
    subject: String,
    nonce: String,
    code_challenge: String,
    redirect_uri: String,
}

/// A signing algorithm the gateway supports for JWT bearer assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionAlgorithm {
    Rs256,
    Es256,
}

impl AssertionAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }

    fn jwt_algorithm(self) -> Algorithm {
        match self {
            Self::Rs256 => Algorithm::RS256,
            Self::Es256 => Algorithm::ES256,
        }
    }
}

impl std::str::FromStr for AssertionAlgorithm {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "RS256" => Ok(Self::Rs256),
            "ES256" => Ok(Self::Es256),
            other => Err(format!("unsupported assertion algorithm '{other}', expected RS256 or ES256")),
        }
    }
}

/// A PKCS#8 signing key generated once per test process, so no private key is committed.
pub struct AssertionSigningKey {
    algorithm: AssertionAlgorithm,
    private_pem: String,
    public_jwk: Value,
}

impl std::fmt::Debug for AssertionSigningKey {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("AssertionSigningKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl AssertionSigningKey {
    pub fn for_algorithm(algorithm: AssertionAlgorithm) -> &'static Self {
        static RSA: OnceLock<AssertionSigningKey> = OnceLock::new();
        static EC: OnceLock<AssertionSigningKey> = OnceLock::new();
        match algorithm {
            AssertionAlgorithm::Rs256 => RSA.get_or_init(generate_rsa_key),
            AssertionAlgorithm::Es256 => EC.get_or_init(generate_ec_key),
        }
    }

    pub fn algorithm(&self) -> AssertionAlgorithm {
        self.algorithm
    }

    pub fn private_pkcs8_pem(&self) -> &str {
        &self.private_pem
    }

    /// The base64 lines of the private key, each of which appears only where the key does.
    pub fn key_material_lines(&self) -> impl Iterator<Item = &str> {
        self.private_pem
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("-----"))
    }

    fn decoding_key(&self) -> Option<DecodingKey> {
        let jwk: Jwk = serde_json::from_value(self.public_jwk.clone()).ok()?;
        DecodingKey::from_jwk(&jwk).ok()
    }
}

fn generate_rsa_key() -> AssertionSigningKey {
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::traits::PublicKeyParts;
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("generate RSA assertion key");
    AssertionSigningKey {
        algorithm: AssertionAlgorithm::Rs256,
        private_pem: key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode RSA assertion key")
            .to_string(),
        public_jwk: serde_json::json!({
            "kty": "RSA", "use": "sig", "alg": "RS256",
            "n": URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
        }),
    }
}

fn generate_ec_key() -> AssertionSigningKey {
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("generate EC assertion key");
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .expect("load EC assertion key");
    let point = pair.public_key().as_ref();
    AssertionSigningKey {
        algorithm: AssertionAlgorithm::Es256,
        private_pem: pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8.as_ref().to_vec())),
        public_jwk: serde_json::json!({
            "kty": "EC", "use": "sig", "alg": "ES256", "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
        }),
    }
}

/// The client the provider trusts to sign JWT bearer assertions.
#[derive(Debug, Clone)]
struct JwtBearerClient {
    issuer: String,
    subject: String,
    key_id: String,
    key: &'static AssertionSigningKey,
}

/// An assertion the provider verified and granted a token for.
#[derive(Debug, Clone)]
pub struct AcceptedAssertion {
    pub algorithm: AssertionAlgorithm,
    pub key_id: Option<String>,
    pub claims: Value,
    /// Unix seconds at which the provider received the assertion.
    pub received_at: u64,
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
    token_endpoint: String,
    jwt_bearer_client: StdMutex<Option<JwtBearerClient>>,
    seen_assertion_ids: StdMutex<HashSet<String>>,
    accepted_assertions: StdMutex<Vec<AcceptedAssertion>>,
}

fn lock<T>(mutex: &StdMutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
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
            token_endpoint: format!("http://127.0.0.1:{}/token", addr.port()),
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
        self.state
            .token_endpoint
            .clone()
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

    /// Trust JWT bearer assertions from `issuer` about `subject`, signed with `key`
    /// under the key id `key_id` and addressed to this token endpoint.
    pub fn trust_assertion_signer(
        &self,
        issuer: &str,
        subject: &str,
        key_id: &str,
        key: &'static AssertionSigningKey,
    ) {
        *lock(&self.state.jwt_bearer_client) = Some(JwtBearerClient {
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            key_id: key_id.to_string(),
            key,
        });
    }

    /// Stop trusting any assertion signer, so every assertion is refused as `invalid_grant`.
    pub fn distrust_assertion_signer(&self) {
        *lock(&self.state.jwt_bearer_client) = None;
    }

    pub fn accepted_assertions(&self) -> Vec<AcceptedAssertion> {
        lock(&self.state.accepted_assertions).clone()
    }
}

fn oauth_error(
    status: StatusCode,
    error: &str,
    description: &str,
) -> Response {
    (status, Json(serde_json::json!({"error": error, "error_description": description}))).into_response()
}

fn gateway_token_response(state: &ProviderState) -> Response {
    Json(serde_json::json!({
        "access_token": state.access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
    }))
    .into_response()
}

/// Verify an assertion against the trusted client: signature, `alg`, `kid`, `iss`, `sub`,
/// `aud` equal to `audience`, an unexpired `exp`, a bounded lifetime and a `jti`.
fn verify_assertion(
    client: &JwtBearerClient,
    audience: &str,
    assertion: &str,
    now: u64,
) -> Result<AcceptedAssertion, &'static str> {
    let header = jsonwebtoken::decode_header(assertion).map_err(|_| "assertion is not a JWT")?;
    if header.alg
        != client
            .key
            .algorithm
            .jwt_algorithm()
    {
        return Err("algorithm mismatch");
    }
    if header.kid.as_deref() != Some(client.key_id.as_str()) {
        return Err("unknown key");
    }
    let decoding_key = client
        .key
        .decoding_key()
        .ok_or("client key unusable")?;
    let mut validation = Validation::new(header.alg);
    validation.leeway = 0;
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);
    validation.set_issuer(&[client.issuer.as_str()]);
    validation.set_audience(&[audience]);
    let claims = jsonwebtoken::decode::<Value>(assertion, &decoding_key, &validation)
        .map_err(|error| match error.kind() {
            ErrorKind::ExpiredSignature => "assertion expired",
            ErrorKind::InvalidSignature => "bad signature",
            ErrorKind::InvalidAudience => "audience mismatch",
            ErrorKind::InvalidIssuer => "issuer mismatch",
            ErrorKind::MissingRequiredClaim(_) => "missing required claim",
            _ => "invalid assertion",
        })?
        .claims;
    if claims["sub"].as_str() != Some(client.subject.as_str()) {
        return Err("subject mismatch");
    }
    let issued_at = claims["iat"]
        .as_u64()
        .unwrap_or(now);
    if issued_at > now + MAX_ASSERTION_IAT_SKEW_SECS {
        return Err("assertion issued in the future");
    }
    let expires_at = claims["exp"]
        .as_u64()
        .unwrap_or(0);
    if expires_at.saturating_sub(issued_at.min(now)) > MAX_ASSERTION_LIFETIME_SECS {
        return Err("assertion lifetime too long");
    }
    if claims["jti"]
        .as_str()
        .is_none_or(str::is_empty)
    {
        return Err("missing jti");
    }
    Ok(AcceptedAssertion {
        algorithm: client.key.algorithm,
        key_id: header.kid,
        claims,
        received_at: now,
    })
}

fn jwt_bearer(
    state: &ProviderState,
    assertion: Option<&str>,
) -> Response {
    let Some(assertion) = assertion.filter(|assertion| !assertion.is_empty()) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "assertion is required");
    };
    let Some(client) = lock(&state.jwt_bearer_client).clone() else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "unknown assertion signer");
    };
    let accepted = match verify_assertion(&client, &state.token_endpoint, assertion, now_secs()) {
        Ok(accepted) => accepted,
        Err(reason) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", reason),
    };
    let assertion_id = format!(
        "{}:{}",
        client.issuer,
        accepted.claims["jti"]
            .as_str()
            .unwrap_or_default()
    );
    if !lock(&state.seen_assertion_ids).insert(assertion_id) {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "assertion replayed");
    }
    lock(&state.accepted_assertions).push(accepted);
    gateway_token_response(state)
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
    if field("grant_type") == Some(JWT_BEARER_GRANT_TYPE) {
        return jwt_bearer(&state, field("assertion"));
    }
    if field("client_id") != Some(OIDC_CLIENT_ID) || field("client_secret") != Some(OIDC_CLIENT_SECRET) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_client"}))).into_response();
    }
    match field("grant_type") {
        Some("authorization_code") => {}
        Some("client_credentials") => return gateway_token_response(&state),
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

    const ISSUER: &str = "gateway@example.test";
    const SUBJECT: &str = "alpha@example.test";
    const KEY_ID: &str = "bdd-gateway-key";

    fn trusted_provider_claims(provider: &OidcProvider) -> Value {
        let now = now_secs();
        serde_json::json!({
            "iss": ISSUER,
            "sub": SUBJECT,
            "aud": provider.token_endpoint(),
            "iat": now - 30,
            "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string(),
        })
    }

    fn sign_assertion(
        key: &AssertionSigningKey,
        key_id: &str,
        claims: &Value,
    ) -> String {
        let mut header = jsonwebtoken::Header::new(
            key.algorithm()
                .jwt_algorithm(),
        );
        header.kid = Some(key_id.to_string());
        let pem = key
            .private_pkcs8_pem()
            .as_bytes();
        let encoding_key = match key.algorithm() {
            AssertionAlgorithm::Rs256 => jsonwebtoken::EncodingKey::from_rsa_pem(pem),
            AssertionAlgorithm::Es256 => jsonwebtoken::EncodingKey::from_ec_pem(pem),
        }
        .expect("assertion key parses");
        jsonwebtoken::encode(&header, claims, &encoding_key).expect("assertion signs")
    }

    async fn jwt_bearer_grant(
        provider: &OidcProvider,
        assertion: &str,
    ) -> (u16, Value) {
        let response = reqwest::Client::new()
            .post(provider.token_endpoint())
            .form(&[("grant_type", JWT_BEARER_GRANT_TYPE), ("assertion", assertion)])
            .send()
            .await
            .expect("token request is sent");
        let status = response.status().as_u16();
        (
            status,
            response
                .json()
                .await
                .expect("token response is JSON"),
        )
    }

    async fn provider_trusting(algorithm: AssertionAlgorithm) -> OidcProvider {
        let provider = OidcProvider::start().await;
        provider.trust_assertion_signer(ISSUER, SUBJECT, KEY_ID, AssertionSigningKey::for_algorithm(algorithm));
        provider
    }

    #[tokio::test]
    async fn jwt_bearer_grant_accepts_rs256_and_es256_assertions_and_records_their_claims() {
        for algorithm in [AssertionAlgorithm::Rs256, AssertionAlgorithm::Es256] {
            let provider = provider_trusting(algorithm).await;
            let claims = trusted_provider_claims(&provider);
            let assertion = sign_assertion(AssertionSigningKey::for_algorithm(algorithm), KEY_ID, &claims);

            let (status, body) = jwt_bearer_grant(&provider, &assertion).await;

            assert_eq!(status, 200, "{algorithm:?}: {body}");
            assert_eq!(body["access_token"], provider.access_token());
            assert_eq!(body["token_type"], "Bearer");
            assert_eq!(provider.token_request_count(), 1);
            let accepted = provider.accepted_assertions();
            assert_eq!(accepted.len(), 1);
            assert_eq!(accepted[0].algorithm, algorithm);
            assert_eq!(accepted[0].key_id.as_deref(), Some(KEY_ID));
            assert_eq!(accepted[0].claims, claims);
        }
    }

    async fn assert_refused(
        provider: &OidcProvider,
        assertion: &str,
        expected_reason: &str,
    ) {
        let (status, body) = jwt_bearer_grant(provider, assertion).await;

        assert_eq!(status, 400, "{body}");
        assert_eq!(body["error"], "invalid_grant");
        assert_eq!(body["error_description"], expected_reason);
        assert!(
            body.get("access_token")
                .is_none()
        );
    }

    #[tokio::test]
    async fn jwt_bearer_grant_refuses_an_assertion_once_the_signer_is_distrusted() {
        let provider = provider_trusting(AssertionAlgorithm::Es256).await;
        provider.distrust_assertion_signer();
        let assertion = sign_assertion(
            AssertionSigningKey::for_algorithm(AssertionAlgorithm::Es256),
            KEY_ID,
            &trusted_provider_claims(&provider),
        );

        assert_refused(&provider, &assertion, "unknown assertion signer").await;
        assert_eq!(provider.token_request_count(), 1);
        assert!(
            provider
                .accepted_assertions()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn jwt_bearer_grant_refuses_a_key_it_does_not_trust() {
        let provider = provider_trusting(AssertionAlgorithm::Es256).await;
        let claims = trusted_provider_claims(&provider);

        let unknown_key_id =
            sign_assertion(AssertionSigningKey::for_algorithm(AssertionAlgorithm::Es256), "another-key", &claims);
        let other_algorithm =
            sign_assertion(AssertionSigningKey::for_algorithm(AssertionAlgorithm::Rs256), KEY_ID, &claims);

        assert_refused(&provider, &unknown_key_id, "unknown key").await;
        assert_refused(&provider, &other_algorithm, "algorithm mismatch").await;
        assert!(
            provider
                .accepted_assertions()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn jwt_bearer_grant_refuses_wrong_issuer_subject_audience_or_expiry() {
        let provider = provider_trusting(AssertionAlgorithm::Rs256).await;
        let key = AssertionSigningKey::for_algorithm(AssertionAlgorithm::Rs256);
        let now = now_secs();
        let cases = [
            ("iss", serde_json::json!("intruder@example.test"), "issuer mismatch"),
            ("sub", serde_json::json!("bravo@example.test"), "subject mismatch"),
            ("aud", serde_json::json!("https://identity.example/token"), "audience mismatch"),
            ("exp", serde_json::json!(now - 1), "assertion expired"),
            ("exp", serde_json::json!(now + MAX_ASSERTION_LIFETIME_SECS + 60), "assertion lifetime too long"),
            ("jti", serde_json::json!(""), "missing jti"),
        ];
        for (claim, value, reason) in cases {
            let mut claims = trusted_provider_claims(&provider);
            claims[claim] = value;

            assert_refused(&provider, &sign_assertion(key, KEY_ID, &claims), reason).await;
        }
        assert!(
            provider
                .accepted_assertions()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn jwt_bearer_grant_refuses_a_replayed_assertion() {
        let provider = provider_trusting(AssertionAlgorithm::Es256).await;
        let assertion = sign_assertion(
            AssertionSigningKey::for_algorithm(AssertionAlgorithm::Es256),
            KEY_ID,
            &trusted_provider_claims(&provider),
        );
        let (first_status, _) = jwt_bearer_grant(&provider, &assertion).await;

        assert_eq!(first_status, 200);
        assert_refused(&provider, &assertion, "assertion replayed").await;
        assert_eq!(provider.token_request_count(), 2);
        assert_eq!(
            provider
                .accepted_assertions()
                .len(),
            1
        );
    }

    #[test]
    fn assertion_signing_key_debug_and_material_lines_hide_nothing_they_should_not() {
        let key = AssertionSigningKey::for_algorithm(AssertionAlgorithm::Es256);

        let debug = format!("{key:?}");
        let lines: Vec<&str> = key
            .key_material_lines()
            .collect();

        assert!(!lines.is_empty());
        assert!(lines.iter().all(|line| {
            !line.contains("PRIVATE KEY")
                && key
                    .private_pkcs8_pem()
                    .contains(line)
        }));
        assert!(
            lines
                .iter()
                .all(|line| !debug.contains(line))
        );
    }

    #[test]
    fn assertion_algorithm_parses_only_the_supported_names() {
        assert_eq!("RS256".parse::<AssertionAlgorithm>(), Ok(AssertionAlgorithm::Rs256));
        assert_eq!("ES256".parse::<AssertionAlgorithm>(), Ok(AssertionAlgorithm::Es256));
        assert!(
            "HS256"
                .parse::<AssertionAlgorithm>()
                .is_err()
        );
    }
}
