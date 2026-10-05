//! Shared reqwest client factory.
//!
//! All outbound HTTP calls to external / user-supplied endpoints must go through
//! one of these builders so that security-relevant defaults (redirect policy,
//! timeout) are applied consistently.
//!
//! ## Builders
//!
//! | Function | Timeout | Redirect | Typical use |
//! |---|---|---|---|
//! | [`external`] | 30 s | `none` | OAuth token exchange, webhooks, integrations |
//! | [`with_short_timeout`] | 10 s | `none` | JWKS fetch, low-latency probes |
//! | [`health_checker`] | 10 s | follows | Health-check probes (endpoints may redirect) |
//! | [`with_timeout`] | caller-supplied | `none` | Pipe executors with per-target timeouts |
//! | [`proxy_with_timeout`] | caller-supplied | `none` | Internal proxy hop with connection pooling |

use std::time::Duration;

use anyhow::{Context, Result};

pub const EXTERNAL_TIMEOUT_SECS: u64 = 30;
pub const SHORT_TIMEOUT_SECS: u64 = 10;

/// Standard client for outbound calls to external / user-supplied endpoints.
///
/// - 30-second request timeout
/// - Redirects disabled (SSRF guard — a redirect to an internal address would
///   bypass the URL validation performed before the first request)
pub fn external() -> Result<reqwest::Client> {
    with_timeout(Duration::from_secs(EXTERNAL_TIMEOUT_SECS))
}

/// Short-timeout client for fast probes (JWKS fetch, low-latency calls).
///
/// - 10-second request timeout
/// - Redirects disabled
pub fn with_short_timeout() -> Result<reqwest::Client> {
    with_timeout(Duration::from_secs(SHORT_TIMEOUT_SECS))
}

/// Client with a caller-supplied timeout, redirects disabled.
///
/// - Caller-supplied request timeout
/// - Redirects disabled
///
/// Use when the timeout is determined at runtime (e.g. per-pipe target config).
pub fn with_timeout(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build HTTP client")
}

/// Connection-pooled client for the Fabric receive forward and agent-card hops.
///
/// - Caller-supplied request timeout
/// - Redirects disabled: a 3xx from a target is returned, never followed, so a
///   target cannot redirect the gateway to another address
/// - Connection pool tuned for sustained agent-to-agent traffic
pub fn proxy_with_timeout(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(30))
        .tcp_keepalive(Duration::from_secs(60))
        .user_agent("Affinidi-Fabric-Agent-Gateway/1.0")
        .build()
        .context("Failed to build proxy HTTP client")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn the_proxy_client_returns_a_redirect_instead_of_following_it() {
        let followed = Arc::new(AtomicUsize::new(0));
        let hits = followed.clone();
        let app = axum::Router::new()
            .route(
                "/start",
                axum::routing::get(|| async {
                    (axum::http::StatusCode::FOUND, [(axum::http::header::LOCATION, "/internal")])
                }),
            )
            .route(
                "/internal",
                axum::routing::get(move || {
                    hits.fetch_add(1, Ordering::SeqCst);
                    async { "internal" }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });

        let response = super::proxy_with_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .get(format!("http://{address}/start"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        assert_eq!(followed.load(Ordering::SeqCst), 0, "the redirect target was fetched");
    }
}
