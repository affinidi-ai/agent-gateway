//! JWT Bearer data models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::jwt_bearer::jwks::Jwk;

/// Where to fetch/find the JSON Web Key Set for a `JwtVerificationStrategy`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JwksSource {
    /// Statically configured keys — no HTTP, no cache.
    Static { jwks: Vec<Jwk> },
    /// URL to fetch the JWKS from (cached per `Cache-Control: max-age`).
    Remote { jwks_uri: String },
}

/// A registered JWT verification strategy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtVerificationStrategy {
    /// Internally generated UUID — immutable after creation.
    pub id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Human-readable name shown in the UI (does not need to be unique).
    pub name: String,

    /// The expected `iss` claim value. Mandatory.
    pub expected_issuer: String,

    /// Where to find the JWKS (static inline keys or a remote URL).
    pub jwks_source: JwksSource,

    /// When this strategy was created.
    pub created_at: DateTime<Utc>,

    /// When this strategy was last updated.
    pub updated_at: DateTime<Utc>,
}

/// JWT Bearer-specific authentication configuration attached to a channel or pipe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JwtBearerAuthConfig {
    /// UUID of the `JwtVerificationStrategy` to use for validation.
    pub jwt_verification_strategy_id: String,

    /// Acceptable `aud` claim values. May be empty — when empty, audience
    /// validation is skipped entirely to accommodate OAuth servers that do not
    /// include an `aud` claim in their access tokens.
    /// The token is accepted if its `aud` claim matches *any* value in this list.
    pub audiences: Vec<String>,

    /// HTTP header to read the token from. Defaults to `Authorization`.
    #[serde(default = "default_token_header")]
    pub token_header: String,

    /// Scheme prefix stripped from the header value before validation (e.g. `Bearer`).
    /// Empty string means "no scheme prefix — header carries the raw token".
    /// Defaults to `Bearer`.
    #[serde(default = "default_token_scheme")]
    pub token_scheme: String,

    /// Forward the validated token header unchanged to the direct target.
    /// Defaults to `false`.
    #[serde(default)]
    pub forward_header: bool,
}

fn default_token_header() -> String {
    "Authorization".to_string()
}

fn default_token_scheme() -> String {
    "Bearer".to_string()
}

impl Default for JwtBearerAuthConfig {
    fn default() -> Self {
        Self {
            jwt_verification_strategy_id: String::new(),
            audiences: Vec::new(),
            token_header: default_token_header(),
            token_scheme: default_token_scheme(),
            forward_header: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_strategy() -> JwtVerificationStrategy {
        JwtVerificationStrategy {
            id: "00000000-0000-0000-0000-000000000001".to_string(),
            tenant_id: None,
            name: "Test Strategy".to_string(),
            expected_issuer: "https://issuer.example.com".to_string(),
            jwks_source: JwksSource::Remote {
                jwks_uri: "https://issuer.example.com/.well-known/jwks.json".to_string(),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // ── Serialisation round-trips ────────────────────────────────────────────

    #[test]
    fn test_jwt_verification_strategy_roundtrip() {
        let strategy = make_strategy();
        let json = serde_json::to_string(&strategy).unwrap();
        let back: JwtVerificationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, strategy.id);
        assert_eq!(back.name, strategy.name);
        assert_eq!(back.expected_issuer, strategy.expected_issuer);
    }

    #[test]
    fn test_jwks_source_remote_roundtrip() {
        let src = JwksSource::Remote {
            jwks_uri: "https://example.com/jwks.json".to_string(),
        };
        let json = serde_json::to_string(&src).unwrap();
        let back: JwksSource = serde_json::from_str(&json).unwrap();
        assert_eq!(back, src);
    }

    #[test]
    fn test_jwks_source_static_roundtrip() {
        let src = JwksSource::Static { jwks: vec![] };
        let json = serde_json::to_string(&src).unwrap();
        let back: JwksSource = serde_json::from_str(&json).unwrap();
        assert_eq!(back, src);
    }

    #[test]
    fn test_expected_issuer_is_mandatory() {
        let strategy = make_strategy();
        assert!(
            !strategy
                .expected_issuer
                .is_empty()
        );
    }
}
