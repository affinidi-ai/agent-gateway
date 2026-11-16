//! Shared test utilities for the oidc module.

use axum::{Router, routing::get};
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub const ED25519_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPiOVQaSEcxl/NogGyUAX88ouBy1bWJFMp4gi0pcCgcY
-----END PRIVATE KEY-----";
/// The base64url `x` of [`ED25519_PRIVATE_PEM`]'s public key.
pub const ED25519_JWK_X: &str = "xMjCoPwAtNcNFrwDLMlggNGrTdN0LAd_kxjJGWg8jZU";

/// An EdDSA JWT over `claims`, signed with [`ED25519_PRIVATE_PEM`] under `kid`.
pub fn sign_ed25519_jwt(
    claims: &serde_json::Value,
    kid: &str,
) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).unwrap();
    encode(&header, claims, &key).unwrap()
}

/// A static-JWKS strategy for `issuer` holding one Ed25519 key with public `x` under `kid`.
/// The JWK has no `alg`, so the token header picks the algorithm.
pub fn static_okp_strategy(
    id: &str,
    tenant_id: Option<&str>,
    issuer: &str,
    kid: &str,
    x: &str,
) -> crate::jwt_bearer::models::JwtVerificationStrategy {
    use crate::jwt_bearer::{jwks::Jwk, models::JwksSource};
    crate::jwt_bearer::models::JwtVerificationStrategy {
        principal_claim: None,
        id: id.to_string(),
        tenant_id: tenant_id.map(str::to_string),
        name: id.to_string(),
        expected_issuer: issuer.to_string(),
        jwks_source: JwksSource::Static {
            jwks: vec![Jwk {
                kty: "OKP".to_string(),
                key_use: Some("sig".to_string()),
                kid: Some(kid.to_string()),
                alg: None,
                n: None,
                e: None,
                crv: Some("Ed25519".to_string()),
                x: Some(x.to_string()),
                y: None,
            }],
        },
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// RAII guard that aborts the spawned server task when dropped, and removes its
/// origin from the JWKS fixtures the client admits.
pub struct TestServer {
    handle: tokio::task::JoinHandle<()>,
    origin: String,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
        if let Ok(mut origins) = JWKS_FIXTURE_ORIGINS.lock() {
            origins.retain(|origin| origin != &self.origin);
        }
    }
}

/// Spin up an in-process JWKS HTTP server that serves `jwks_body` at
/// `GET /.well-known/jwks.json`.
///
/// `max_age` controls the `Cache-Control: max-age=N` response header.
/// When `None`, no `Cache-Control` header is sent.
///
/// Returns the base URL and a [`TestServer`] guard; the server is shut down
/// when the guard is dropped.
pub async fn start_jwks_server(
    jwks_body: String,
    max_age: Option<u64>,
) -> (String, TestServer) {
    let app = Router::new().route(
        "/.well-known/jwks.json",
        get(move || {
            let body = jwks_body.clone();
            async move {
                let mut builder = axum::response::Response::builder()
                    .status(200)
                    .header("Content-Type", "application/json");
                if let Some(age) = max_age {
                    builder = builder.header("Cache-Control", format!("max-age={}", age));
                }
                builder
                    .body(axum::body::Body::from(body))
                    .unwrap()
            }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .unwrap();
    });

    let origin = format!("http://{}", addr);
    JWKS_FIXTURE_ORIGINS
        .lock()
        .unwrap()
        .push(origin.clone());
    (origin.clone(), TestServer { handle, origin })
}

/// The origins of the running loopback JWKS servers [`start_jwks_server`] started,
/// which the JWKS client admits although the Configured egress policy refuses loopback.
static JWKS_FIXTURE_ORIGINS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

pub fn jwks_fixture_origins() -> Vec<String> {
    JWKS_FIXTURE_ORIGINS
        .lock()
        .unwrap()
        .clone()
}

/// Build a minimal JWKS JSON body with a single RSA key.
pub fn rsa_jwks_body(
    kid: &str,
    n: &str,
    e: &str,
) -> String {
    format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","use":"sig","alg":"RS256","n":"{n}","e":"{e}"}}]}}"#,
        kid = kid,
        n = n,
        e = e,
    )
}
