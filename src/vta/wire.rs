//! VTA auth/Trust-Task **response** wire types.
//!
//! Modelled from the VTA repo's canonical shapes
//! (`vta-sdk::protocols::auth`) — the source of truth — so the gateway's thin
//! REST client deserialises exactly what the VTA emits. Request documents are
//! built as `serde_json::Value` in [`super::client`] (so the signed bytes and
//! the sent bytes are identical).

use serde::Deserialize;

/// `auth/challenge/0.1#response`: the gateway consumes `challenge` + `sessionId`
/// (the `expiresAt` the VTA also returns is ignored — serde drops it).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub challenge: String,
    pub session_id: String,
}

/// Canonical `TokenBundle` (RFC 6749 §5.1-shaped). `expiresIn` is seconds from
/// issuance.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenBundle {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    pub expires_in: u64,
    #[serde(default)]
    pub refresh_expires_in: Option<u64>,
}

// Hand-written Debug: the access/refresh tokens are bearer credentials and must
// never reach a log via `{:?}` (mirrors the VTA SDK's own redaction).
impl std::fmt::Debug for TokenBundle {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("TokenBundle")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self
                    .refresh_token
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("refresh_expires_in", &self.refresh_expires_in)
            .finish()
    }
}

/// `auth/authenticate/0.2#response`: `{ session, tokens }`. Only `tokens` is
/// consumed; the `session` object is ignored (serde drops unknown fields).
#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticateResponse {
    pub tokens: TokenBundle,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The access/refresh tokens are bearer credentials; a `{:?}` capture (e.g.
    /// a tracing span or panic) must not leak them.
    #[test]
    fn token_bundle_debug_is_redacted() {
        let bundle = TokenBundle {
            access_token: "access-token-SECRET".to_string(),
            refresh_token: Some("refresh-token-SECRET".to_string()),
            token_type: Some("Bearer".to_string()),
            expires_in: 900,
            refresh_expires_in: Some(86_400),
        };
        let shown = format!("{bundle:?}");
        assert!(!shown.contains("SECRET"), "tokens must be redacted in Debug: {shown}");
        assert!(shown.contains("<redacted>"), "redaction marker present");
        assert!(shown.contains("900"), "non-secret fields still shown");
    }
}
