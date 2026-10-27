//! Typed errors for the VTA signing connector.
//!
//! The gateway talks to the VTA over HTTP; these variants let callers map a VTA
//! failure to a stable gateway response (VTA-04) **without** echoing VTA
//! internals into client-facing error bodies. Transport detail stays in logs.

use std::fmt;

/// Why a VTA operation failed.
#[derive(Debug)]
pub enum VtaError {
    /// Building or signing the auth/Trust-Task document failed locally (bad
    /// control key, JCS/serialisation error) — never reached the VTA.
    Signing(String),
    /// The HTTP request to the VTA could not be sent or timed out.
    Transport(String),
    /// The VTA returned a non-success HTTP status. `status` is the code; `body`
    /// is captured for server-side logs only, never surfaced to a caller.
    Http { status: u16, body: String },
    /// The VTA's response could not be parsed into the expected shape.
    Protocol(String),
    /// The connector is misconfigured (missing coordinates, bad DID, etc.).
    Config(String),
    /// The signing quota for the current window is exhausted (VTA-17). The
    /// detail names the limit and a retry hint; it carries no secrets.
    QuotaExceeded(String),
}

impl fmt::Display for VtaError {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        match self {
            // Deliberately terse and free of secrets/tokens: a `VtaError` may be
            // logged or wrapped, and auth documents + bearer tokens must never
            // appear in its text.
            Self::Signing(_) => write!(f, "VTA auth document signing failed"),
            Self::Transport(_) => write!(f, "VTA transport error"),
            Self::Http { status, .. } => write!(f, "VTA returned HTTP {status}"),
            Self::Protocol(_) => write!(f, "VTA response was not understood"),
            Self::Config(_) => write!(f, "VTA connector is misconfigured"),
            // Safe to surface: the detail is a limit and a retry hint, built by
            // the gateway from its own configuration — no VTA internals.
            Self::QuotaExceeded(detail) => write!(f, "VTA signing quota exceeded: {detail}"),
        }
    }
}

impl std::error::Error for VtaError {}

impl VtaError {
    /// Operator-facing detail for **server-side logs only** — may name the
    /// failing step but still never contains token material (the token types
    /// carry their own redacted `Debug`).
    pub fn log_detail(&self) -> &str {
        match self {
            Self::Signing(d) | Self::Transport(d) | Self::Protocol(d) | Self::Config(d) | Self::QuotaExceeded(d) => d,
            Self::Http { body, .. } => body,
        }
    }

    /// Whether the operation may be safely retried once: a transport-level
    /// failure (connection/timeout), or a `429` in which the agent explicitly
    /// told us to come back.
    ///
    /// A `429` is **safer** to retry than a transport failure, not riskier: it
    /// is a definite response meaning the request was rejected before being
    /// processed, whereas a timeout may have been processed. Any other definite
    /// HTTP response, and local signing/config errors, are not retried.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Transport(_) | Self::Http { status: 429, .. })
    }

    /// How long the agent asked us to wait, from a `429` body's
    /// `retryAfterSecs`.
    ///
    /// Capped at [`Self::MAX_RETRY_AFTER`]: signing sits on the request path,
    /// so a misconfigured or hostile agent must not be able to pin a caller's
    /// request open by naming a large delay. Absent or unparseable means retry
    /// without waiting, matching the transport case.
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        let Self::Http { status: 429, body } = self else {
            return None;
        };
        let secs = serde_json::from_str::<serde_json::Value>(body)
            .ok()?
            .get("retryAfterSecs")?
            .as_f64()?;
        if !secs.is_finite() || secs <= 0.0 {
            return None;
        }
        Some(std::time::Duration::from_secs_f64(secs).min(Self::MAX_RETRY_AFTER))
    }

    /// Upper bound on an agent-requested wait before the single retry.
    pub const MAX_RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The agent signals back-pressure with a 429 and a wait; ignoring it
    /// fails a caller's signature that a one-second pause would have served.
    #[test]
    fn a_rate_limited_response_is_retryable_and_carries_its_wait() {
        let err = VtaError::Http {
            status: 429,
            body: r#"{"error":"rate_limited","limiter":"auth","retryAfterSecs":1}"#.to_string(),
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(1)));
    }

    /// Signing is on the request path, so an agent naming a huge delay must
    /// not be able to hold a caller's request open.
    #[test]
    fn an_agent_requested_wait_is_capped() {
        let err = VtaError::Http {
            status: 429,
            body: r#"{"retryAfterSecs":3600}"#.to_string(),
        };
        assert_eq!(err.retry_after(), Some(VtaError::MAX_RETRY_AFTER));
    }

    /// A 429 without a usable hint still retries, just without waiting.
    #[test]
    fn a_rate_limit_without_a_hint_retries_immediately() {
        for body in [r#"{"error":"rate_limited"}"#, "not json", r#"{"retryAfterSecs":-5}"#] {
            let err = VtaError::Http {
                status: 429,
                body: body.to_string(),
            };
            assert!(err.is_retryable(), "still retryable: {body}");
            assert_eq!(err.retry_after(), None, "no wait: {body}");
        }
    }

    /// Every other definite response is the agent's answer, not back-pressure:
    /// retrying a refusal wastes the budget and doubles the audit noise.
    #[test]
    fn other_http_failures_are_not_retried() {
        for status in [400, 401, 403, 404, 500, 503] {
            let err = VtaError::Http { status, body: "{}".to_string() };
            assert!(!err.is_retryable(), "HTTP {status} must not retry");
            assert_eq!(err.retry_after(), None);
        }
        assert!(!VtaError::Config("bad".into()).is_retryable());
        assert!(!VtaError::Signing("bad".into()).is_retryable());
        assert!(VtaError::Transport("timeout".into()).is_retryable());
    }

    /// A VTA response body could echo a bearer token; the error's `Display`
    /// (which may be logged or returned) must never surface it — only the status.
    #[test]
    fn http_display_never_leaks_the_response_body() {
        let token = "access-token-SECRET-eyJhbGciOiJFZERTQSJ9";
        let err = VtaError::Http {
            status: 401,
            body: format!("{{\"token\":\"{token}\"}}"),
        };
        let shown = format!("{err}");
        assert!(shown.contains("401"), "status is surfaced: {shown}");
        assert!(!shown.contains(token), "token material must not appear in Display: {shown}");
        assert!(!shown.contains("token"), "no body echo in Display: {shown}");
        // The body is available for server-side logs via log_detail (by design).
        assert!(
            err.log_detail()
                .contains(token)
        );
    }

    #[test]
    fn other_variants_display_without_echoing_detail() {
        for err in [
            VtaError::Signing("sensitive-detail".to_string()),
            VtaError::Transport("sensitive-detail".to_string()),
            VtaError::Protocol("sensitive-detail".to_string()),
            VtaError::Config("sensitive-detail".to_string()),
        ] {
            assert!(!format!("{err}").contains("sensitive-detail"), "Display is generic");
        }
    }
}
