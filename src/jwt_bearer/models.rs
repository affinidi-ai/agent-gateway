//! JWT Bearer data models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::jwt_bearer::errors::JwtBearerError;
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

    /// The claim whose value names the caller. Absent means `sub`. It decides
    /// the caller's identity hash, so it is fixed at creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_claim: Option<String>,

    /// When this strategy was created.
    pub created_at: DateTime<Utc>,

    /// When this strategy was last updated.
    pub updated_at: DateTime<Utc>,
}

pub const DEFAULT_PRINCIPAL_CLAIM: &str = "sub";

const MAX_PRINCIPAL_CLAIM_LEN: usize = 128;

/// Registered claims that name the token, its issuer, audience, client,
/// tenant, session or lifetime rather than a person. Naming one would put
/// every caller that shares its value, such as a whole tenant or application,
/// under one identity hash.
const NON_IDENTIFYING_CLAIMS: [&str; 21] = [
    "iss",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "azp",
    "client_id",
    "tid",
    "idp",
    "scope",
    "scp",
    "nonce",
    "sid",
    "act",
    "cnf",
    "typ",
    "ver",
    "auth_time",
    "amr",
    "acr",
];

impl JwtVerificationStrategy {
    /// The claim that names this strategy's callers. A stored claim the API
    /// would refuse, such as one written to storage by hand, is an error rather
    /// than a caller name, so a strategy naming `iss` identifies nobody.
    pub fn principal_claim_name(&self) -> Result<&str, JwtBearerError> {
        match self
            .principal_claim
            .as_deref()
        {
            None => Ok(DEFAULT_PRINCIPAL_CLAIM),
            Some(claim) => normalize_principal_claim(Some(claim))
                .map(|_| claim)
                .map_err(JwtBearerError::InvalidPrincipalClaim),
        }
    }

    /// Lowercase hex SHA-256 of what decides which tokens this strategy
    /// accepts and whom they name: the expected issuer, the JWKS source and
    /// the principal claim. Its name and timestamps are left out, so renaming
    /// it keeps the digest. Audiences and algorithms are not the strategy's:
    /// the Caller Context method that uses it sets them. `None` for a strategy
    /// whose principal claim names nobody.
    pub fn verification_digest(&self) -> Option<String> {
        use sha2::{Digest, Sha256};
        let principal_claim = self
            .principal_claim_name()
            .ok()?;
        let encoded = serde_json_canonicalizer::to_vec(&serde_json::json!({
            "expected_issuer": self.expected_issuer,
            "jwks_source": self.jwks_source,
            "principal_claim": principal_claim,
        }))
        .ok()?;
        Some(hex::encode(Sha256::digest(encoded)))
    }

    /// The stored claim in the form the API stores it: `None` for `sub`.
    pub fn normalized_principal_claim(&self) -> Result<Option<String>, JwtBearerError> {
        normalize_principal_claim(
            self.principal_claim
                .as_deref(),
        )
        .map_err(JwtBearerError::InvalidPrincipalClaim)
    }
}

/// Check a requested principal claim and return its stored form: `None` for the
/// default `sub`, so a strategy that names `sub` and one that names nothing are
/// the same strategy.
pub fn normalize_principal_claim(claim: Option<&str>) -> Result<Option<String>, String> {
    let Some(claim) = claim else {
        return Ok(None);
    };
    if let Some(problem) = identifying_claim_problem(claim) {
        return Err(format!("principal_claim {problem}"));
    }
    Ok((claim != DEFAULT_PRINCIPAL_CLAIM).then(|| claim.to_string()))
}

/// What keeps `claim` from naming a caller, worded to follow the setting's name: it must be
/// 1 to 128 printable ASCII characters with no spaces, and not a claim that names the token,
/// its issuer, audience, client, tenant, session or lifetime rather than a person.
pub fn identifying_claim_problem(claim: &str) -> Option<String> {
    if claim.is_empty() || claim.len() > MAX_PRINCIPAL_CLAIM_LEN {
        Some(format!("must be 1 to {MAX_PRINCIPAL_CLAIM_LEN} characters"))
    } else if !claim
        .bytes()
        .all(|byte| byte.is_ascii_graphic())
    {
        Some("must be printable ASCII with no spaces".to_string())
    } else if NON_IDENTIFYING_CLAIMS.contains(&claim) {
        Some(format!("cannot be '{claim}': it does not identify a caller"))
    } else {
        None
    }
}

/// The claim a JWT Bearer method matches against its `audiences`.
///
/// `aud` binds the token to the service it was issued for. `azp` and
/// `client_id` bind it only to the client it was issued to, for identity
/// providers whose access tokens carry no `aud`: a token that client was
/// issued for another service is accepted too, so callers it verifies get
/// no per-user delegated credentials: a save refuses it beside a binding
/// whose `consent_mode` is `on_demand`, `pre_authorize` or `elicit`, and a
/// binding with external consent or delegated credentials for Fabric callers
/// are withheld.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AudienceClaim {
    #[default]
    Aud,
    Azp,
    ClientId,
}

impl AudienceClaim {
    pub fn is_aud(&self) -> bool {
        *self == Self::Aud
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aud => "aud",
            Self::Azp => "azp",
            Self::ClientId => "client_id",
        }
    }
}

/// JWT Bearer-specific authentication configuration attached to a channel or pipe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JwtBearerAuthConfig {
    /// Stable identifier of this method within its `methods` list, assigned by
    /// the dashboard and kept across edits and reordering. Names the method an
    /// inbound identity is derived from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// UUID of the `JwtVerificationStrategy` to use for validation.
    pub jwt_verification_strategy_id: String,

    /// Acceptable values of the `audience_claim` claim. The token is accepted
    /// if that claim matches *any* value in this list. A save must name at
    /// least one, unless the Access Point publishes a protected resource. A
    /// method stored with an empty list, from before that rule, skips the
    /// audience check and is warned about at startup and on each save.
    pub audiences: Vec<String>,

    /// The claim `audiences` is matched against. Defaults to `aud`.
    #[serde(default, skip_serializing_if = "AudienceClaim::is_aud")]
    pub audience_claim: AudienceClaim,

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
            id: None,
            jwt_verification_strategy_id: String::new(),
            audiences: Vec::new(),
            audience_claim: AudienceClaim::Aud,
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
            principal_claim: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn the_verification_digest_changes_only_with_what_verifies_and_names_a_caller() {
        let strategy = make_strategy();
        let digest = strategy
            .verification_digest()
            .unwrap();
        assert_eq!(digest.len(), 64, "{digest}");
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );

        let mut unchanged = strategy.clone();
        unchanged.name = "Renamed".to_string();
        unchanged.updated_at = Utc::now() + chrono::Duration::days(1);
        unchanged.principal_claim = Some(DEFAULT_PRINCIPAL_CLAIM.to_string());
        assert_eq!(unchanged.verification_digest(), Some(digest.clone()));

        let mut issuer = strategy.clone();
        issuer.expected_issuer = "https://other.example.com".to_string();
        let mut jwks = strategy.clone();
        jwks.jwks_source = JwksSource::Remote {
            jwks_uri: "https://issuer.example.com/other-jwks.json".to_string(),
        };
        let mut inline = strategy.clone();
        inline.jwks_source = JwksSource::Static { jwks: Vec::new() };
        let mut claim = strategy.clone();
        claim.principal_claim = Some("oid".to_string());
        for (field, changed) in [("issuer", issuer), ("jwks_uri", jwks), ("static jwks", inline), ("claim", claim)] {
            assert_ne!(changed.verification_digest(), Some(digest.clone()), "{field}");
        }

        let mut refused = strategy;
        refused.principal_claim = Some("iss".to_string());
        assert_eq!(refused.verification_digest(), None);
    }

    #[test]
    fn the_principal_claim_defaults_to_sub_and_is_stored_only_when_it_is_not() {
        let mut strategy = make_strategy();
        assert_eq!(
            strategy
                .principal_claim_name()
                .unwrap(),
            "sub"
        );
        assert!(
            !serde_json::to_string(&strategy)
                .unwrap()
                .contains("principal_claim")
        );
        strategy.principal_claim = Some("oid".to_string());
        assert_eq!(
            strategy
                .principal_claim_name()
                .unwrap(),
            "oid"
        );
        let back: JwtVerificationStrategy = serde_json::from_str(&serde_json::to_string(&strategy).unwrap()).unwrap();
        assert_eq!(
            back.principal_claim
                .as_deref(),
            Some("oid")
        );
        let legacy: JwtVerificationStrategy = serde_json::from_value(serde_json::json!({
            "id": "1", "name": "n", "expected_issuer": "https://i", "jwks_source": { "type": "static", "jwks": [] },
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(
            legacy
                .principal_claim_name()
                .unwrap(),
            "sub"
        );
    }

    #[test]
    fn a_stored_principal_claim_the_api_would_refuse_names_no_caller() {
        let mut strategy = make_strategy();
        strategy.principal_claim = Some("sub".to_string());
        assert_eq!(
            strategy
                .principal_claim_name()
                .unwrap(),
            "sub"
        );
        assert_eq!(
            strategy
                .normalized_principal_claim()
                .unwrap(),
            None
        );
        for refused in ["iss", "", "o id"] {
            strategy.principal_claim = Some(refused.to_string());
            assert!(
                matches!(strategy.principal_claim_name(), Err(JwtBearerError::InvalidPrincipalClaim(_))),
                "{refused:?}"
            );
            assert!(
                strategy
                    .normalized_principal_claim()
                    .is_err()
            );
        }
    }

    #[test]
    fn a_principal_claim_is_normalised_or_refused() {
        assert_eq!(normalize_principal_claim(None), Ok(None));
        assert_eq!(normalize_principal_claim(Some("sub")), Ok(None));
        assert_eq!(normalize_principal_claim(Some("oid")), Ok(Some("oid".to_string())));
        assert_eq!(
            normalize_principal_claim(Some("https://example.com/claims/user_id")),
            Ok(Some("https://example.com/claims/user_id".to_string()))
        );
        for refused in [
            "",
            " oid",
            "o id",
            "oid\n",
            "caf\u{e9}",
            "iss",
            "aud",
            "exp",
            "iat",
            "nbf",
            "jti",
            "azp",
            "client_id",
            "tid",
            "idp",
            "scope",
            "scp",
            "nonce",
            "sid",
            "act",
            "cnf",
            "typ",
            "ver",
            "auth_time",
            "amr",
            "acr",
        ] {
            assert!(normalize_principal_claim(Some(refused)).is_err(), "{refused:?}");
        }
        assert!(normalize_principal_claim(Some(&"x".repeat(129))).is_err());
        assert!(normalize_principal_claim(Some(&"x".repeat(128))).is_ok());
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

    #[test]
    fn audience_claim_defaults_to_aud_and_is_left_out_when_aud() {
        let config: JwtBearerAuthConfig = serde_json::from_value(serde_json::json!({
            "jwt_verification_strategy_id": "idp", "audiences": ["api://agent"]
        }))
        .unwrap();
        assert_eq!(config.audience_claim, AudienceClaim::Aud);
        assert!(
            serde_json::to_value(&config)
                .unwrap()
                .get("audience_claim")
                .is_none()
        );
    }

    #[test]
    fn audience_claim_round_trips_client_id_and_azp() {
        for (claim, name) in [(AudienceClaim::ClientId, "client_id"), (AudienceClaim::Azp, "azp")] {
            let config: JwtBearerAuthConfig = serde_json::from_value(serde_json::json!({
                "jwt_verification_strategy_id": "idp", "audiences": ["app"], "audience_claim": name
            }))
            .unwrap();
            assert_eq!(config.audience_claim, claim);
            assert_eq!(claim.as_str(), name);
            assert_eq!(serde_json::to_value(&config).unwrap()["audience_claim"], name);
        }
    }

    #[test]
    fn audience_claim_refuses_a_claim_that_does_not_bind_the_token() {
        for name in ["sub", "email", "iss", ""] {
            let parsed = serde_json::from_value::<JwtBearerAuthConfig>(serde_json::json!({
                "jwt_verification_strategy_id": "idp", "audiences": ["x"], "audience_claim": name
            }));
            assert!(parsed.is_err(), "audience_claim '{name}' should be refused");
        }
    }
}
