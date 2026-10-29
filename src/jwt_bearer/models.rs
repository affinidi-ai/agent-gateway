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

/// An empty static key set, which verifies no token.
impl Default for JwksSource {
    fn default() -> Self {
        Self::Static { jwks: Vec::new() }
    }
}

/// Authorization server metadata pinned on a strategy by discovery.
pub use crate::authz_metadata::AuthzServerMetadata as AuthorizationServerMetadata;

/// A registered JWT verification strategy configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

    /// Authorization server metadata pinned by discovery. STS, consent and credential
    /// provider flows ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<AuthorizationServerMetadata>,

    /// When this strategy was created.
    pub created_at: DateTime<Utc>,

    /// When this strategy was last updated.
    pub updated_at: DateTime<Utc>,
}

impl JwtVerificationStrategy {
    /// The remote JWKS URI, if the key set is fetched.
    pub fn remote_jwks_uri(&self) -> Option<&str> {
        match &self.jwks_source {
            JwksSource::Remote { jwks_uri } => Some(jwks_uri),
            JwksSource::Static { .. } => None,
        }
    }
}

/// Refuse an empty issuer and an issuer template such as Entra's `{tenantid}`.
///
/// Tokens are matched to the issuer exactly, so a template never matches a token;
/// only tenant-specific authorities can be used.
pub fn validate_expected_issuer(issuer: &str) -> Result<(), &'static str> {
    if issuer.trim().is_empty() {
        return Err("expected_issuer must not be empty");
    }
    if issuer.contains(['{', '}']) {
        return Err("expected_issuer must be one concrete issuer, not a template such as {tenantid}");
    }
    Ok(())
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
            name: "Test Strategy".to_string(),
            expected_issuer: "https://issuer.example.com".to_string(),
            jwks_source: JwksSource::Remote {
                jwks_uri: "https://issuer.example.com/.well-known/jwks.json".to_string(),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
            ..Default::default()
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
    fn a_strategy_saved_before_discovery_existed_round_trips_unchanged() {
        let stored = serde_json::json!({
            "id": "s1",
            "name": "Legacy",
            "expected_issuer": "https://issuer.example.com",
            "jwks_source": { "type": "remote", "jwks_uri": "https://issuer.example.com/jwks.json" },
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        });
        let strategy: JwtVerificationStrategy = serde_json::from_value(stored.clone()).unwrap();
        assert_eq!(strategy.authorization_server, None);
        assert_eq!(serde_json::to_value(&strategy).unwrap(), stored);
    }

    #[test]
    fn pinned_metadata_round_trips() {
        let strategy = JwtVerificationStrategy {
            authorization_server: Some(AuthorizationServerMetadata {
                issuer: "https://issuer.example.com".to_string(),
                metadata_url: "https://issuer.example.com/.well-known/oauth-authorization-server".to_string(),
                token_endpoint: "https://issuer.example.com/token".to_string(),
                jwks_uri: "https://issuer.example.com/jwks.json".to_string(),
            }),
            ..make_strategy()
        };
        let back: JwtVerificationStrategy = serde_json::from_str(&serde_json::to_string(&strategy).unwrap()).unwrap();
        assert_eq!(back.authorization_server, strategy.authorization_server);
    }

    #[test]
    fn issuer_templates_and_empty_issuers_are_refused() {
        assert!(validate_expected_issuer("https://login.microsoftonline.com/8f6c2e1a/v2.0").is_ok());
        assert!(validate_expected_issuer("did:web:gw.example.com").is_ok());
        for issuer in ["", "  ", "https://login.microsoftonline.com/{tenantid}/v2.0", "https://x/{tid"] {
            assert!(validate_expected_issuer(issuer).is_err(), "{issuer:?}");
        }
    }

    #[test]
    fn remote_jwks_uri_is_absent_for_a_static_key_set() {
        assert_eq!(make_strategy().remote_jwks_uri(), Some("https://issuer.example.com/.well-known/jwks.json"));
        let static_keys = JwtVerificationStrategy {
            jwks_source: JwksSource::default(),
            ..make_strategy()
        };
        assert_eq!(static_keys.remote_jwks_uri(), None);
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
