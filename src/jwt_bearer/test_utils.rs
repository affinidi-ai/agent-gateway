//! Shared test utilities for the oidc module.

use axum::{Router, routing::get};
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// RAII guard that aborts the spawned server task when dropped.
pub struct TestServer(pub tokio::task::JoinHandle<()>);

impl Drop for TestServer {
    fn drop(&mut self) {
        self.0.abort();
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

    (format!("http://{}", addr), TestServer(handle))
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
