//! An in-process OAuth 2.0 authorization server for tests.
//!
//! It serves RFC 8414 and OpenID Connect discovery documents for a configurable
//! issuer (plain origin, trailing slash, or path issuer), a JWKS holding an RSA
//! and an EC key with rotation, the `client_credentials` grant, and the RFC 7523
//! `jwt-bearer` grant. Every request is counted and logged without credentials,
//! and the claims of every accepted assertion are kept.
//! Faults make an endpoint answer 404, an oversized body, or a mismatched issuer.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use super::oidc_keys::{SigningFixture, jwks_document};

pub const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub const CLIENT_CREDENTIALS_GRANT: &str = "client_credentials";
pub const OVERSIZED_BODY_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_ASSERTION_LIFETIME_SECS: u64 = 3600;
pub const MAX_ASSERTION_IAT_SKEW_SECS: u64 = 60;
const DEFAULT_AUDIENCE: &str = "mock-resource";
const TOKEN_TTL_SECS: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Discovery,
    Jwks,
    Token,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    None,
    NotFound,
    Oversized,
    IssuerMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerShape {
    Origin,
    TrailingSlash,
    Path(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryDocs {
    Both,
    Rfc8414Only,
    OpenIdOnly,
}

#[derive(Debug, Clone)]
pub struct JwtBearerClient {
    pub iss: String,
    pub sub: String,
    pub keys: Vec<SigningFixture>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedRequest {
    pub endpoint: Option<Endpoint>,
    pub method: String,
    pub path: String,
    pub grant_type: Option<String>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub audience: Option<String>,
    pub status: u16,
}

struct KeySet {
    generation: usize,
    published: Vec<SigningFixture>,
    signing: SigningFixture,
}

struct Shared {
    base_url: String,
    issuer: String,
    prefix: String,
    discovery: DiscoveryDocs,
    signing_alg: Algorithm,
    accept_issuer_audience: bool,
    keys: Mutex<KeySet>,
    faults: Mutex<HashMap<Endpoint, Fault>>,
    clients: Mutex<HashMap<String, String>>,
    jwt_clients: Mutex<HashMap<String, JwtBearerClient>>,
    seen_jti: Mutex<HashSet<String>>,
    accepted_assertions: Mutex<Vec<Value>>,
    log: Mutex<Vec<LoggedRequest>>,
    token_requests: AtomicUsize,
    issued: AtomicUsize,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

pub struct MockAuthServerBuilder {
    shape: IssuerShape,
    discovery: DiscoveryDocs,
    signing_alg: Algorithm,
    accept_issuer_audience: bool,
}

impl MockAuthServerBuilder {
    pub fn accept_issuer_audience(
        mut self,
        accept: bool,
    ) -> Self {
        self.accept_issuer_audience = accept;
        self
    }

    pub fn issuer_shape(
        mut self,
        shape: IssuerShape,
    ) -> Self {
        self.shape = shape;
        self
    }

    pub fn discovery(
        mut self,
        discovery: DiscoveryDocs,
    ) -> Self {
        self.discovery = discovery;
        self
    }

    pub fn signing_alg(
        mut self,
        alg: Algorithm,
    ) -> Self {
        assert!(matches!(alg, Algorithm::RS256 | Algorithm::ES256), "the mock signs with RS256 or ES256");
        self.signing_alg = alg;
        self
    }

    pub async fn start(self) -> MockAuthServer {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr: SocketAddr = listener
            .local_addr()
            .expect("listener address");
        let base_url = format!("http://{addr}");
        let (issuer, prefix) = match self.shape {
            IssuerShape::Origin => (base_url.clone(), String::new()),
            IssuerShape::TrailingSlash => (format!("{base_url}/"), String::new()),
            IssuerShape::Path(path) => {
                assert!(path.starts_with('/'), "a path issuer starts with '/'");
                (
                    format!("{base_url}{path}"),
                    path.trim_end_matches('/')
                        .to_string(),
                )
            }
        };
        let rsa = SigningFixture::rs256(0);
        let ec = SigningFixture::es256(0);
        let signing = if self.signing_alg == Algorithm::RS256 {
            rsa.clone()
        } else {
            ec.clone()
        };
        let shared = Arc::new(Shared {
            base_url,
            issuer,
            prefix,
            discovery: self.discovery,
            signing_alg: self.signing_alg,
            accept_issuer_audience: self.accept_issuer_audience,
            keys: Mutex::new(KeySet {
                generation: 0,
                published: vec![rsa, ec],
                signing,
            }),
            faults: Mutex::new(HashMap::new()),
            clients: Mutex::new(HashMap::new()),
            jwt_clients: Mutex::new(HashMap::new()),
            seen_jti: Mutex::new(HashSet::new()),
            accepted_assertions: Mutex::new(Vec::new()),
            log: Mutex::new(Vec::new()),
            token_requests: AtomicUsize::new(0),
            issued: AtomicUsize::new(0),
        });
        let app = Router::new()
            .fallback(handle)
            .with_state(shared.clone());
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        MockAuthServer { shared, handle }
    }
}

pub struct MockAuthServer {
    shared: Arc<Shared>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for MockAuthServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl std::fmt::Debug for MockAuthServer {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("MockAuthServer")
            .field("issuer", &self.shared.issuer)
            .finish()
    }
}

impl MockAuthServer {
    pub fn builder() -> MockAuthServerBuilder {
        MockAuthServerBuilder {
            shape: IssuerShape::Origin,
            discovery: DiscoveryDocs::Both,
            signing_alg: Algorithm::RS256,
            accept_issuer_audience: false,
        }
    }

    pub async fn start() -> Self {
        Self::builder().start().await
    }

    pub fn issuer(&self) -> &str {
        &self.shared.issuer
    }

    pub fn origin(&self) -> &str {
        &self.shared.base_url
    }

    pub fn token_endpoint(&self) -> String {
        format!("{}{}/token", self.shared.base_url, self.shared.prefix)
    }

    pub fn jwks_uri(&self) -> String {
        format!("{}{}/jwks.json", self.shared.base_url, self.shared.prefix)
    }

    pub fn rfc8414_metadata_url(&self) -> String {
        format!("{}/.well-known/oauth-authorization-server{}", self.shared.base_url, self.shared.prefix)
    }

    pub fn openid_configuration_url(&self) -> String {
        format!("{}{}/.well-known/openid-configuration", self.shared.base_url, self.shared.prefix)
    }

    pub fn egress_allowlist(&self) -> String {
        self.shared.base_url.clone()
    }

    pub fn oauth_endpoint_allowlist(&self) -> String {
        [self.token_endpoint(), self.jwks_uri(), self.rfc8414_metadata_url(), self.openid_configuration_url()].join(",")
    }

    pub fn register_client(
        &self,
        client_id: &str,
        client_secret: &str,
    ) {
        lock(&self.shared.clients).insert(client_id.to_string(), client_secret.to_string());
    }

    pub fn register_jwt_client(
        &self,
        client: JwtBearerClient,
    ) {
        lock(&self.shared.jwt_clients).insert(client.iss.clone(), client);
    }

    pub fn set_fault(
        &self,
        endpoint: Endpoint,
        fault: Fault,
    ) {
        lock(&self.shared.faults).insert(endpoint, fault);
    }

    pub fn clear_faults(&self) {
        lock(&self.shared.faults).clear();
    }

    pub fn signing_key(&self) -> SigningFixture {
        lock(&self.shared.keys)
            .signing
            .clone()
    }

    pub fn published_kids(&self) -> Vec<String> {
        lock(&self.shared.keys)
            .published
            .iter()
            .map(|key| key.kid.clone())
            .collect()
    }

    pub fn rotate_keys(
        &self,
        keep_previous: bool,
    ) {
        let mut keys = lock(&self.shared.keys);
        keys.generation += 1;
        let generation = keys.generation;
        assert!(generation < SigningFixture::GENERATIONS, "the fixtures provide one rotation");
        let rsa = SigningFixture::rs256(generation);
        let ec = SigningFixture::es256(generation);
        keys.signing = if self.shared.signing_alg == Algorithm::RS256 {
            rsa.clone()
        } else {
            ec.clone()
        };
        let mut published = if keep_previous {
            std::mem::take(&mut keys.published)
        } else {
            Vec::new()
        };
        published.push(rsa);
        published.push(ec);
        keys.published = published;
    }

    pub fn requests(&self) -> Vec<LoggedRequest> {
        lock(&self.shared.log).clone()
    }

    pub fn accepted_assertions(&self) -> Vec<Value> {
        lock(
            &self
                .shared
                .accepted_assertions,
        )
        .clone()
    }

    pub fn request_count(
        &self,
        endpoint: Endpoint,
    ) -> usize {
        lock(&self.shared.log)
            .iter()
            .filter(|entry| entry.endpoint == Some(endpoint))
            .count()
    }

    pub fn token_request_count(&self) -> usize {
        self.shared
            .token_requests
            .load(Ordering::SeqCst)
    }
}

#[derive(Clone, Copy)]
enum Route {
    Rfc8414,
    OpenId,
    Jwks,
    Token,
}

impl Route {
    fn endpoint(self) -> Endpoint {
        match self {
            Route::Rfc8414 | Route::OpenId => Endpoint::Discovery,
            Route::Jwks => Endpoint::Jwks,
            Route::Token => Endpoint::Token,
        }
    }
}

fn route_for(
    shared: &Shared,
    path: &str,
) -> Option<Route> {
    let prefix = &shared.prefix;
    let rfc8414 = format!("/.well-known/oauth-authorization-server{prefix}");
    let openid = format!("{prefix}/.well-known/openid-configuration");
    let openid_inserted = format!("/.well-known/openid-configuration{prefix}");
    if path == rfc8414 {
        return (shared.discovery != DiscoveryDocs::OpenIdOnly).then_some(Route::Rfc8414);
    }
    if path == openid || (!prefix.is_empty() && path == openid_inserted) {
        return (shared.discovery != DiscoveryDocs::Rfc8414Only).then_some(Route::OpenId);
    }
    if path == format!("{prefix}/jwks.json") {
        return Some(Route::Jwks);
    }
    if path == format!("{prefix}/token") {
        return Some(Route::Token);
    }
    None
}

fn json_response(
    status: StatusCode,
    body: &Value,
) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body.to_string()).into_response()
}

fn oauth_error(
    status: StatusCode,
    error: &str,
    description: &str,
) -> Response {
    json_response(status, &json!({ "error": error, "error_description": description }))
}

fn oversized_response() -> Response {
    let body = format!(r#"{{"pad":"{}"}}"#, "a".repeat(OVERSIZED_BODY_BYTES));
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn metadata_document(
    shared: &Shared,
    route: Route,
    mismatched: bool,
) -> Value {
    let issuer = if mismatched {
        format!(
            "{}/impostor",
            shared
                .issuer
                .trim_end_matches('/')
        )
    } else {
        shared.issuer.clone()
    };
    let mut doc = json!({
        "issuer": issuer,
        "token_endpoint": format!("{}{}/token", shared.base_url, shared.prefix),
        "jwks_uri": format!("{}{}/jwks.json", shared.base_url, shared.prefix),
        "grant_types_supported": [CLIENT_CREDENTIALS_GRANT, JWT_BEARER_GRANT],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "scopes_supported": ["read", "write"],
    });
    if matches!(route, Route::OpenId) {
        doc["subject_types_supported"] = json!(["public"]);
        doc["response_types_supported"] = json!(["code"]);
        doc["id_token_signing_alg_values_supported"] = json!(["RS256", "ES256"]);
    }
    doc
}

fn record(
    shared: &Shared,
    mut entry: LoggedRequest,
    response: Response,
) -> Response {
    entry.status = response.status().as_u16();
    lock(&shared.log).push(entry);
    response
}

async fn handle(
    State(shared): State<Arc<Shared>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().to_string();
    let mut entry = LoggedRequest {
        endpoint: None,
        method: method.to_string(),
        path: path.clone(),
        grant_type: None,
        client_id: None,
        scope: None,
        audience: None,
        status: 0,
    };
    let Some(route) = route_for(&shared, &path) else {
        return record(&shared, entry, oauth_error(StatusCode::NOT_FOUND, "not_found", "unknown path"));
    };
    let endpoint = route.endpoint();
    entry.endpoint = Some(endpoint);

    let expected = if matches!(route, Route::Token) {
        Method::POST
    } else {
        Method::GET
    };
    if method != expected {
        return record(
            &shared,
            entry,
            oauth_error(StatusCode::METHOD_NOT_ALLOWED, "invalid_request", "method not allowed"),
        );
    }

    let fault = lock(&shared.faults)
        .get(&endpoint)
        .copied()
        .unwrap_or(Fault::None);
    match fault {
        Fault::NotFound => {
            return record(&shared, entry, oauth_error(StatusCode::NOT_FOUND, "not_found", "fault injected"));
        }
        Fault::Oversized => return record(&shared, entry, oversized_response()),
        Fault::None | Fault::IssuerMismatch => {}
    }
    let mismatched = fault == Fault::IssuerMismatch;

    let response = match route {
        Route::Rfc8414 | Route::OpenId => json_response(StatusCode::OK, &metadata_document(&shared, route, mismatched)),
        Route::Jwks => {
            let keys = lock(&shared.keys)
                .published
                .clone();
            json_response(StatusCode::OK, &jwks_document(&keys))
        }
        Route::Token => {
            shared
                .token_requests
                .fetch_add(1, Ordering::SeqCst);
            token_endpoint(&shared, &headers, &body, mismatched, &mut entry)
        }
    };
    record(&shared, entry, response)
}

fn token_endpoint(
    shared: &Shared,
    headers: &HeaderMap,
    body: &[u8],
    mismatched: bool,
    entry: &mut LoggedRequest,
) -> Response {
    let form: HashMap<String, String> = url::form_urlencoded::parse(body)
        .into_owned()
        .collect();
    entry.grant_type = form
        .get("grant_type")
        .cloned();
    entry.scope = form.get("scope").cloned();
    entry.audience = form
        .get("audience")
        .or_else(|| form.get("resource"))
        .cloned();

    match form
        .get("grant_type")
        .map(String::as_str)
    {
        Some(CLIENT_CREDENTIALS_GRANT) => client_credentials(shared, headers, &form, mismatched, entry),
        Some(JWT_BEARER_GRANT) => jwt_bearer(shared, &form, mismatched),
        _ => oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type", "grant type not supported"),
    }
}

fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = String::from_utf8(
        STANDARD
            .decode(encoded)
            .ok()?,
    )
    .ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

fn client_credentials(
    shared: &Shared,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
    mismatched: bool,
    entry: &mut LoggedRequest,
) -> Response {
    let (client_id, secret) = match basic_credentials(headers) {
        Some(pair) => pair,
        None => match (form.get("client_id"), form.get("client_secret")) {
            (Some(id), Some(secret)) => (id.clone(), secret.clone()),
            _ => return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "client authentication required"),
        },
    };
    entry.client_id = Some(client_id.clone());
    let known = lock(&shared.clients)
        .get(&client_id)
        .is_some_and(|expected| *expected == secret);
    if !known {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "client authentication failed");
    }
    issue_token(shared, &client_id, form, mismatched)
}

fn unverified_claims(assertion: &str) -> Option<Value> {
    let payload = assertion.split('.').nth(1)?;
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?,
    )
    .ok()
}

fn invalid_grant(description: &str) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", description)
}

fn jwt_bearer(
    shared: &Shared,
    form: &HashMap<String, String>,
    mismatched: bool,
) -> Response {
    let Some(assertion) = form.get("assertion") else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "assertion is required");
    };
    let Ok(header) = jsonwebtoken::decode_header(assertion) else {
        return invalid_grant("assertion is not a JWT");
    };
    if !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256) {
        return invalid_grant("unsupported alg");
    }
    let Some(kid) = header.kid.clone() else {
        return invalid_grant("missing kid");
    };
    let Some(claims) = unverified_claims(assertion) else {
        return invalid_grant("assertion payload unreadable");
    };
    let Some(iss) = claims["iss"].as_str() else {
        return invalid_grant("missing claim iss");
    };
    let Some(client) = lock(&shared.jwt_clients)
        .get(iss)
        .cloned()
    else {
        return invalid_grant("unknown issuer");
    };
    let Some(key) = client
        .keys
        .iter()
        .find(|key| key.kid == kid)
    else {
        return invalid_grant("unknown kid");
    };
    let Ok(jwk) = serde_json::from_value::<Jwk>(key.public_jwk()) else {
        return invalid_grant("client key unusable");
    };
    let Ok(decoding_key) = DecodingKey::from_jwk(&jwk) else {
        return invalid_grant("client key unusable");
    };

    let token_endpoint = format!("{}{}/token", shared.base_url, shared.prefix);
    let mut validation = Validation::new(header.alg);
    validation.leeway = 0;
    validation.validate_exp = true;
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);
    if shared.accept_issuer_audience {
        validation.set_audience(&[token_endpoint.as_str(), shared.issuer.as_str()]);
    } else {
        validation.set_audience(&[token_endpoint.as_str()]);
    }
    validation.set_issuer(&[client.iss.as_str()]);
    let verified = match jsonwebtoken::decode::<Value>(assertion, &decoding_key, &validation) {
        Ok(data) => data.claims,
        Err(err) => {
            return invalid_grant(match err.kind() {
                ErrorKind::ExpiredSignature => "assertion expired",
                ErrorKind::InvalidSignature => "bad signature",
                ErrorKind::InvalidAudience => "audience mismatch",
                ErrorKind::InvalidIssuer => "issuer mismatch",
                ErrorKind::MissingRequiredClaim(_) => "missing required claim",
                ErrorKind::InvalidAlgorithm => "algorithm mismatch",
                _ => "invalid assertion",
            });
        }
    };

    if verified["sub"].as_str() != Some(client.sub.as_str()) {
        return invalid_grant("sub mismatch");
    }
    let now = now_secs();
    let issued_at = verified["iat"]
        .as_u64()
        .unwrap_or(now);
    let exp = verified["exp"]
        .as_u64()
        .unwrap_or(0);
    if issued_at > now + MAX_ASSERTION_IAT_SKEW_SECS {
        return invalid_grant("assertion issued in the future");
    }
    if exp.saturating_sub(now) > MAX_ASSERTION_LIFETIME_SECS
        || exp.saturating_sub(issued_at) > MAX_ASSERTION_LIFETIME_SECS
    {
        return invalid_grant("assertion lifetime too long");
    }
    let Some(jti) = verified["jti"]
        .as_str()
        .filter(|jti| !jti.is_empty())
    else {
        return invalid_grant("missing jti");
    };
    if !lock(&shared.seen_jti).insert(format!("{}:{jti}", client.iss)) {
        return invalid_grant("jti replayed");
    }
    lock(&shared.accepted_assertions).push(verified);
    issue_token(shared, &client.sub, form, mismatched)
}

fn issue_token(
    shared: &Shared,
    subject: &str,
    form: &HashMap<String, String>,
    mismatched: bool,
) -> Response {
    let now = now_secs();
    let sequence = shared
        .issued
        .fetch_add(1, Ordering::SeqCst);
    let issuer = if mismatched {
        format!(
            "{}/impostor",
            shared
                .issuer
                .trim_end_matches('/')
        )
    } else {
        shared.issuer.clone()
    };
    let audience = form
        .get("audience")
        .or_else(|| form.get("resource"))
        .map(String::as_str)
        .unwrap_or(DEFAULT_AUDIENCE);
    let scope = form.get("scope");
    let mut claims = json!({
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": now,
        "exp": now + TOKEN_TTL_SECS,
        "jti": format!("mock-token-{sequence}"),
    });
    if let Some(scope) = scope {
        claims["scope"] = json!(scope);
    }
    let access_token = lock(&shared.keys)
        .signing
        .sign(&claims);
    let mut body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL_SECS,
    });
    if let Some(scope) = scope {
        body["scope"] = json!(scope);
    }
    json_response(StatusCode::OK, &body)
}
