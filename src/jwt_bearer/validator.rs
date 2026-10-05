//! JWT Bearer token verification
//!
//! [`JwtBearerVerifier`] performs local JWT verification:
//! 1. Decode the JWT header to extract the `kid`.
//! 2. Fetch the matching JWK via [`crate::jwt_bearer::jwks::JwksClient`] (Remote) or
//!    [`crate::jwt_bearer::jwks::get_static_key`] (Static).
//! 3. Verify the signature and standard claims (`exp`, `iss`, `aud`).
//! 4. Return all decoded claims as [`serde_json::Value`].

use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, decode_header};
use serde_json::Value;
use tracing::{debug, info, warn};

use crate::jwt_bearer::{
    errors::{JwtBearerError, JwtBearerResult},
    jwks::JwksClient,
    models::{JwksSource, JwtVerificationStrategy},
};

/// All decoded JWT claims, returned on successful validation.
pub type Claims = Value;

/// Extract the bearer token from a raw header value.
///
/// `scheme` is the authentication scheme keyword (e.g. `Bearer`). When non-empty,
/// the header value must start with `"{scheme} "` and the prefix is stripped.
/// When empty, the entire trimmed header value is treated as the token.
///
/// Returns `MissingToken` when the header is absent, the scheme prefix is required
/// but absent, or the resulting token portion is empty after trimming.
pub fn extract_bearer_with_scheme<'a>(
    header_value: Option<&'a str>,
    scheme: &str,
) -> JwtBearerResult<&'a str> {
    let raw = header_value.ok_or(JwtBearerError::MissingToken)?;
    let token = if scheme.is_empty() {
        raw.trim()
    } else {
        let prefix = format!("{} ", scheme);
        raw.strip_prefix(prefix.as_str())
            .ok_or(JwtBearerError::MissingToken)?
            .trim()
    };
    if token.is_empty() {
        return Err(JwtBearerError::MissingToken);
    }
    Ok(token)
}

/// Validates incoming bearer tokens against a `JwtVerificationStrategy` configuration.
pub struct JwtBearerVerifier {
    jwks_client: Arc<JwksClient>,
}

impl JwtBearerVerifier {
    /// Create a new verifier backed by the given JWKS client.
    pub fn new(jwks_client: Arc<JwksClient>) -> Self {
        Self { jwks_client }
    }

    /// Return the underlying JWKS client.
    pub fn jwks_client(&self) -> Arc<JwksClient> {
        Arc::clone(&self.jwks_client)
    }

    /// Validate `token` against `strategy` and check `aud` against `audiences`.
    ///
    /// On success returns the full decoded claims payload.
    /// On any failure returns a specific [`JwtBearerError`] variant.
    pub async fn validate(
        &self,
        token: &str,
        strategy: &JwtVerificationStrategy,
        audiences: &[String],
    ) -> JwtBearerResult<Claims> {
        // 1. Decode header to get kid and algorithm
        let header: Header = decode_header(token)
            .map_err(|e| JwtBearerError::InvalidToken(format!("Failed to decode JWT header: {}", e)))?;

        let kid = header
            .kid
            .clone()
            .unwrap_or_default();
        debug!(strategy_id = %strategy.id, kid = %kid, "Validating JWT");

        // 2. Fetch the matching JWK from the configured source
        let jwk = match &strategy.jwks_source {
            JwksSource::Remote { jwks_uri } => {
                self.jwks_client
                    .get_key(&strategy.id, jwks_uri, &kid)
                    .await?
            }
            JwksSource::Static { jwks } => crate::jwt_bearer::jwks::get_static_key(jwks, &kid)?,
        };

        // 4. Build the decoding key from the JWK
        let decoding_key = decoding_key_from_jwk(&jwk)?;

        // 5. Build validation
        let algorithm = algorithm_from_jwk(&jwk, &header)?;

        let mut validation = Validation::new(algorithm);

        // Delegate iss validation to jsonwebtoken.
        validation.set_issuer(&[strategy
            .expected_issuer
            .as_str()]);

        let mut required_spec_claims = vec!["iss", "exp"];

        // An empty list disables the audience check. That is a supported shape:
        // some OAuth servers do not put `aud` on their access tokens at all, and
        // the BDD suite exercises exactly that. It is still a weaker posture,
        // because a token minted for another service of the same issuer is then
        // accepted, so say so once rather than failing closed and breaking every
        // deployment that relies on it. Requiring an allow-list is a
        // supported-issuer decision, not a code fix.
        if audiences.is_empty() {
            warn!(
                strategy_id = %strategy.id,
                "No audience allow-list configured: a token minted for another service of the same issuer will be accepted"
            );
            validation.validate_aud = false;
        } else {
            validation.set_audience(audiences);
            required_spec_claims.push("aud");
        }

        validation.set_required_spec_claims(&required_spec_claims);

        // 6. Decode and verify signature + exp + iss + aud
        let token_data = decode::<Value>(token, &decoding_key, &validation).map_err(|e| {
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::ExpiredSignature => JwtBearerError::ExpiredToken,
                ErrorKind::InvalidIssuer => JwtBearerError::InvalidIssuer,
                ErrorKind::MissingRequiredClaim(claim) if claim == "iss" => JwtBearerError::InvalidAudience,
                ErrorKind::InvalidAudience => JwtBearerError::InvalidAudience,
                ErrorKind::MissingRequiredClaim(claim) if claim == "aud" => JwtBearerError::InvalidAudience,
                _ => JwtBearerError::InvalidToken(format!("JWT verification failed: {}", e)),
            }
        })?;

        let claims = token_data.claims;

        info!(
            strategy_id = %strategy.id,
            iss = %claims.get("iss").and_then(|v| v.as_str()).unwrap_or("<none>"),
            sub = %claims.get("sub").and_then(|v| v.as_str()).unwrap_or("<none>"),
            "JWT validation successful"
        );

        Ok(claims)
    }
}

// ── Key and algorithm helpers ─────────────────────────────────────────────────

/// Build a [`DecodingKey`] from a [`crate::jwt_bearer::jwks::Jwk`].
fn decoding_key_from_jwk(jwk: &crate::jwt_bearer::jwks::Jwk) -> JwtBearerResult<DecodingKey> {
    match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk
                .n
                .as_deref()
                .ok_or_else(|| JwtBearerError::InvalidToken("RSA JWK missing 'n'".to_string()))?;
            let e = jwk
                .e
                .as_deref()
                .ok_or_else(|| JwtBearerError::InvalidToken("RSA JWK missing 'e'".to_string()))?;
            DecodingKey::from_rsa_components(n, e)
                .map_err(|e| JwtBearerError::InvalidToken(format!("Failed to build RSA decoding key: {}", e)))
        }
        "EC" => {
            let x = jwk
                .x
                .as_deref()
                .ok_or_else(|| JwtBearerError::InvalidToken("EC JWK missing 'x'".to_string()))?;
            let y = jwk
                .y
                .as_deref()
                .ok_or_else(|| JwtBearerError::InvalidToken("EC JWK missing 'y'".to_string()))?;
            DecodingKey::from_ec_components(x, y)
                .map_err(|e| JwtBearerError::InvalidToken(format!("Failed to build EC decoding key: {}", e)))
        }
        "OKP" => {
            let x = jwk
                .x
                .as_deref()
                .ok_or_else(|| JwtBearerError::InvalidToken("OKP JWK missing 'x'".to_string()))?;
            DecodingKey::from_ed_components(x)
                .map_err(|e| JwtBearerError::InvalidToken(format!("Failed to build EdDSA decoding key: {}", e)))
        }
        other => Err(JwtBearerError::InvalidToken(format!("Unsupported JWK key type: {}", other))),
    }
}

/// Determine the [`Algorithm`] to use, preferring the JWK `alg` field,
/// then falling back to the JWT header `alg`.
fn algorithm_from_jwk(
    jwk: &crate::jwt_bearer::jwks::Jwk,
    header: &Header,
) -> JwtBearerResult<Algorithm> {
    let alg_str = jwk
        .alg
        .as_deref()
        .unwrap_or_else(|| algorithm_str_from_jsonwebtoken(header.alg));

    parse_algorithm(alg_str)
}

fn algorithm_str_from_jsonwebtoken(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        Algorithm::ES256 => "ES256",
        Algorithm::ES384 => "ES384",
        Algorithm::EdDSA => "EdDSA",
        _ => "RS256",
    }
}

fn parse_algorithm(s: &str) -> JwtBearerResult<Algorithm> {
    match s {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EdDSA" => Ok(Algorithm::EdDSA),
        other => Err(JwtBearerError::InvalidToken(format!("Unsupported JWT algorithm: {}", other))),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt_bearer::{
        jwks::JwksClient,
        models::{JwksSource, JwtVerificationStrategy},
    };
    use chrono::Utc;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    // ── test key helpers ──────────────────────────────────────────────────────

    // RSA 2048-bit test key pair — PKCS#8 format required by jsonwebtoken
    // Generated with: openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt
    const RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCfb6QB1jGDn74Z
eMrQxOmWjkCr3M9M2PAx2Y++MRNu7iARmPnVCNu5WTcSXVJdkq85YBZPg1G37OH2
8ULyedS5C70cofqowAaRYAwiB0QzRczQD6ixHMFr2QsHzEwv6ZN7K4f9yImAxRys
XpH4jznguqKa3FdPlVHT1RW8wd2Rq+EIGxE8VVs7OumHy+oS2NXmFCVDgvUBmxZQ
8MemA0E6WA3Pnlpw4g1XWcO6q6a5d8pDOcVjjhVhIZU27JGBLckYSpoRoXKFHWrj
k2M9AT3wZl3qL5seUN/MzOH8+13pTCnRQ1KptgRpdBONhHoCnCgA/6LHWEfs7D4E
e3OXGuEBAgMBAAECggEAKklL8IjE3SozG0JkWHbBlYLpOCv6d2FaY35Wl5UgmF1j
+AbgzFXrIP++kYpa3CKZgtgvUqt7sxKK5BodLX6Oov2wDLYRa0xy8X/N+ACBYC/1
IIHmtgLwchBA0rKmylZjHVnwWakkfxjIgBcdFBW4vhgCJJyoM51g9JQhjczFXWsT
NrCJE1HxKKseEE9mKmBQLDr6eu1FmKsDPSr6WfXPBAmeD1lZdAxR2XQxFGsxvl0T
01047FywcJ3mz6rK7FmoEJVlKP1wR14YIoUFutyarw/UdraxKuTzdgv+W/+ZFNXZ
sxv0ZSK/xdEh7T8lhWgvl+WVvb+qXVS8xz9fyfJzmQKBgQDe5ZFmY6MsSRh3l4Su
jocOCO2tTsMcnynzZ/oh4tEUlElQFaBj1H7Ks0kzvmpsA2mPjPlhl9rrv5SeA0rL
pyKmbE9VXHhqFPRAJ12nUElOL/piPQqDk+NkIZMa/zS7JUMvP+OincCO6h9by+gk
DX1FinBHPL2GPZ5kuAnOUMRxnwKBgQC3HVPqAHJB4HyKGcoRZgCfPILU1No62ySF
95IBF0oyKL5TUW7L6K52XlehntEtX8wKGnlaYEA+b+IZ6CwPF2QskL4uUMuyzGGc
iw+GurKcmlt+sAO4Z5v1gzuY+0XW3dqjEfQIwFvGX+Nnv7WvlU4tA7HTfr4aERxF
7oHcR1XpXwKBgBsNXbJBkYJEdNW+6/mLjtSjPMV187Q7lQnXqsIGFz4aKTOxDEBR
f/n1/IJtL9lgKKWlhHbVyVonbFApMiC5bjkomBBSIsMtO9+1Z2ZxFhSJOihGJEqH
3mc+s+3o32t/QEIxzNzlrIMr4xZvDwOhJ30TKkFbG915CQpMU9RYdR8dAoGBAJox
dgHr0kqqz/QydzdjX063U6wIeKNq+TxeFnIYvH+0U2AxiEzoaFCAbOZJp/a/Xj97
v4hc2Hw7FneeS8uBdPcaAytZGc470E5TwwU+nTzFthnd+aQEiw2YLk1J+atPMdZz
Pb1IzX8kK4enpURvQ18gZ1OivE2S7u3sQynMYAmdAoGBAKhcBN0NawbQai9ZKFl1
HGdtaC/rYGbGsQ6K0m73pyRsPNv7HN6YMiNm+6i+xapEZ5FLWTFbQpahIwCw9jKa
qcCMWzlqjbrYRlpUKNFD3/iAu6qiowZSpTXCgUaxxOz459ii+/JN6xkZ0fSneMGn
BNGV7kU9kiKxYO6H5k+Yb+kp
-----END PRIVATE KEY-----";

    // The base64url-encoded `n` and `e` components of the public key above.
    // Derived from the PKCS#8 private key using the RSA modulus and public exponent.
    // n is the base64url of the 2048-bit modulus (big-endian, no leading zero padding)
    // e = AQAB = 65537
    const RSA_JWK_N: &str = "n2-kAdYxg5--GXjK0MTplo5Aq9zPTNjwMdmPvjETbu4gEZj51QjbuVk3El1SXZKvOWAWT4NRt-zh9vFC8nnUuQu9HKH6qMAGkWAMIgdEM0XM0A-osRzBa9kLB8xML-mTeyuH_ciJgMUcrF6R-I854LqimtxXT5VR09UVvMHdkavhCBsRPFVbOzrph8vqEtjV5hQlQ4L1AZsWUPDHpgNBOlgNz55acOINV1nDuqumuXfKQznFY44VYSGVNuyRgS3JGEqaEaFyhR1q45NjPQE98GZd6i-bHlDfzMzh_Ptd6Uwp0UNSqbYEaXQTjYR6ApwoAP-ix1hH7Ow-BHtzlxrhAQ";
    const RSA_JWK_E: &str = "AQAB";

    fn make_strategy() -> JwtVerificationStrategy {
        JwtVerificationStrategy {
            id: "test-strategy-id".to_string(),
            tenant_id: None,
            name: "Test IdP".to_string(),
            expected_issuer: "https://issuer.example.com".to_string(),
            jwks_source: JwksSource::Remote {
                jwks_uri: String::new(), // overridden per-test
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Build a signed RS256 JWT with the given claims payload.
    fn make_token(
        claims: serde_json::Value,
        kid: &str,
    ) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let key = EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    // ── stub JWKS client backed by the test RSA public key ────────────────────

    use crate::jwt_bearer::test_utils::{TestServer, rsa_jwks_body, start_jwks_server};

    async fn start_test_jwks_server(kid: &str) -> (String, TestServer) {
        start_jwks_server(rsa_jwks_body(kid, RSA_JWK_N, RSA_JWK_E), Some(3600)).await
    }

    fn make_validator_with_pem_key(jwks_base_url: &str) -> (JwtBearerVerifier, JwtVerificationStrategy) {
        let jwks_client = Arc::new(JwksClient::new());
        let validator = JwtBearerVerifier::new(Arc::clone(&jwks_client));
        let mut strategy = make_strategy();
        strategy.jwks_source = JwksSource::Remote {
            jwks_uri: format!("{}/.well-known/jwks.json", jwks_base_url),
        };
        (validator, strategy)
    }

    // ── validator tests using in-process JWKS server ──────────────────────────

    #[tokio::test]
    async fn test_valid_token_returns_claims() {
        let kid = "test-key-1";
        let (base, _handle) = start_test_jwks_server(kid).await;
        let (validator, strategy) = make_validator_with_pem_key(&base);

        let exp = now_secs() + 3600;
        let claims = json!({
            "iss": "https://issuer.example.com",
            "sub": "user-123",
            "aud": "https://api.example.com",
            "exp": exp
        });
        let token = make_token(claims, kid);

        let result = validator
            .validate(&token, &strategy, &["https://api.example.com".to_string()])
            .await;

        let decoded = result.expect("valid token should pass validation");
        assert_eq!(decoded["sub"], "user-123");
        assert_eq!(decoded["iss"], "https://issuer.example.com");
        assert_eq!(decoded["aud"], "https://api.example.com");
    }

    #[tokio::test]
    async fn test_wrong_signature_returns_error() {
        let kid = "test-key-sig";
        let (base, _handle) = start_test_jwks_server(kid).await;
        let (validator, strategy) = make_validator_with_pem_key(&base);

        let exp = now_secs() + 3600;
        let claims = json!({
            "iss": "https://issuer.example.com",
            "sub": "user-123",
            "aud": "https://api.example.com",
            "exp": exp
        });

        let token = make_token(claims, kid);
        let tampered = format!("{}X", token);

        let result = validator
            .validate(&tampered, &strategy, &["https://api.example.com".to_string()])
            .await;

        assert!(matches!(result, Err(JwtBearerError::InvalidToken(_))), "tampered token should be rejected");
    }

    #[tokio::test]
    async fn test_wrong_issuer_returns_error() {
        let kid = "test-key-iss";
        let (base, _handle) = start_test_jwks_server(kid).await;
        let (validator, strategy) = make_validator_with_pem_key(&base);

        let exp = now_secs() + 3600;
        let claims = json!({
            "iss": "https://evil.example.com",
            "sub": "user-123",
            "aud": "https://api.example.com",
            "exp": exp
        });
        let token = make_token(claims, kid);

        let result = validator
            .validate(&token, &strategy, &["https://api.example.com".to_string()])
            .await;

        assert!(matches!(result, Err(JwtBearerError::InvalidIssuer)), "wrong issuer should be rejected");
    }

    #[tokio::test]
    async fn test_wrong_audience_returns_error() {
        let kid = "test-key-aud";
        let (base, _handle) = start_test_jwks_server(kid).await;
        let (validator, strategy) = make_validator_with_pem_key(&base);

        let exp = now_secs() + 3600;
        let claims = json!({
            "iss": "https://issuer.example.com",
            "sub": "user-123",
            "aud": "https://wrong.example.com",
            "exp": exp
        });
        let token = make_token(claims, kid);

        let result = validator
            .validate(&token, &strategy, &["https://api.example.com".to_string()])
            .await;

        assert!(matches!(result, Err(JwtBearerError::InvalidAudience)), "wrong audience should be rejected");
    }

    #[tokio::test]
    async fn test_missing_aud_claim_rejected_when_audiences_configured() {
        let kid = "test-key-aud-missing";
        let (base, _handle) = start_test_jwks_server(kid).await;
        let (validator, strategy) = make_validator_with_pem_key(&base);

        let exp = now_secs() + 3600;
        let claims = json!({
            "iss": "https://issuer.example.com",
            "sub": "user-123",
            "exp": exp
        });
        let token = make_token(claims, kid);

        let result = validator
            .validate(&token, &strategy, &["https://api.example.com".to_string()])
            .await;

        if let Ok(claims) = &result {
            info!("why");
            panic!(
                "token with no aud claim should be rejected when audiences are configured, but got claims: {:?}",
                claims
            );
        }

        assert!(
            matches!(result, Err(JwtBearerError::InvalidAudience)),
            "token with no aud claim should be rejected when audiences are configured"
        );
    }

    #[tokio::test]
    async fn test_array_audience_accepted_when_one_matches() {
        let kid = "test-key-aud-arr";
        let (base, _handle) = start_test_jwks_server(kid).await;
        let (validator, strategy) = make_validator_with_pem_key(&base);

        let exp = now_secs() + 3600;
        let claims = json!({
            "iss": "https://issuer.example.com",
            "sub": "user-123",
            "aud": ["https://other.example.com", "https://api.example.com"],
            "exp": exp
        });
        let token = make_token(claims, kid);

        let result = validator
            .validate(&token, &strategy, &["https://api.example.com".to_string()])
            .await;

        assert!(result.is_ok(), "token with matching aud in array should pass");
    }

    #[tokio::test]
    async fn test_empty_audiences_skips_aud_validation() {
        let kid = "test-key-no-aud";
        let (base, _handle) = start_test_jwks_server(kid).await;
        let (validator, strategy) = make_validator_with_pem_key(&base);

        let exp = now_secs() + 3600;
        let claims = json!({
            "iss": "https://issuer.example.com",
            "sub": "user-no-aud",
            "exp": exp,
        });
        let token = make_token(claims, kid);

        // Supported shape: issuers that omit `aud`. The weaker posture it implies
        // is warned about at validation time, see the note in `validate`.
        validator
            .validate(&token, &strategy, &[])
            .await
            .expect("a token with no aud is accepted when no allow-list is configured");
    }

    #[tokio::test]
    async fn test_expired_token_returns_expired_error() {
        let kid = "test-key-exp";
        let (base, _handle) = start_test_jwks_server(kid).await;
        let (validator, strategy) = make_validator_with_pem_key(&base);

        let exp = now_secs() - 3600;
        let claims = json!({
            "iss": "https://issuer.example.com",
            "sub": "user-123",
            "aud": "https://api.example.com",
            "exp": exp
        });
        let token = make_token(claims, kid);

        let result = validator
            .validate(&token, &strategy, &["https://api.example.com".to_string()])
            .await;

        assert!(matches!(result, Err(JwtBearerError::ExpiredToken)), "expired token should be rejected");
    }

    #[test]
    fn test_parse_algorithm_supported() {
        assert!(matches!(parse_algorithm("RS256"), Ok(Algorithm::RS256)));
        assert!(matches!(parse_algorithm("RS384"), Ok(Algorithm::RS384)));
        assert!(matches!(parse_algorithm("RS512"), Ok(Algorithm::RS512)));
        assert!(matches!(parse_algorithm("ES256"), Ok(Algorithm::ES256)));
        assert!(matches!(parse_algorithm("ES384"), Ok(Algorithm::ES384)));
    }

    #[test]
    fn test_parse_algorithm_unsupported_returns_error() {
        assert!(parse_algorithm("HS256").is_err());
        assert!(parse_algorithm("none").is_err());
    }

    // ── static JwksSource tests ───────────────────────────────────────────────

    /// Build a [`JwtVerificationStrategy`] whose JWKS is provided inline (static),
    /// using the same RSA public-key components as the remote-server tests.
    fn make_static_strategy(kid: &str) -> JwtVerificationStrategy {
        use crate::jwt_bearer::jwks::Jwk;
        let jwk = Jwk {
            kty: "RSA".to_string(),
            key_use: Some("sig".to_string()),
            kid: Some(kid.to_string()),
            alg: Some("RS256".to_string()),
            n: Some(RSA_JWK_N.to_string()),
            e: Some(RSA_JWK_E.to_string()),
            crv: None,
            x: None,
            y: None,
        };
        JwtVerificationStrategy {
            id: "static-strategy-id".to_string(),
            tenant_id: None,
            name: "Static Test IdP".to_string(),
            expected_issuer: "https://issuer.example.com".to_string(),
            jwks_source: JwksSource::Static { jwks: vec![jwk] },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_static_jwks_valid_token_returns_claims() {
        let kid = "static-key-1";
        let strategy = make_static_strategy(kid);

        // Validator still needs a JwksClient even though static mode never calls it.
        let validator = JwtBearerVerifier::new(Arc::new(JwksClient::new()));

        let exp = now_secs() + 3600;
        let token = make_token(
            json!({
                "iss": "https://issuer.example.com",
                "sub": "static-user",
                "aud": "https://api.example.com",
                "exp": exp,
            }),
            kid,
        );

        let result = validator
            .validate(&token, &strategy, &["https://api.example.com".to_string()])
            .await;

        let decoded = result.expect("valid token with static JWK should pass validation");
        assert_eq!(decoded["sub"], "static-user");
        assert_eq!(decoded["iss"], "https://issuer.example.com");
    }

    #[tokio::test]
    async fn test_static_jwks_missing_kid_returns_key_not_found() {
        // Strategy carries a key for "static-key-present" but the token uses "missing-kid".
        let strategy = make_static_strategy("static-key-present");

        let validator = JwtBearerVerifier::new(Arc::new(JwksClient::new()));

        let exp = now_secs() + 3600;
        let token = make_token(
            json!({
                "iss": "https://issuer.example.com",
                "sub": "static-user",
                "aud": "https://api.example.com",
                "exp": exp,
            }),
            "missing-kid", // kid not present in static JWKS
        );

        let result = validator
            .validate(&token, &strategy, &["https://api.example.com".to_string()])
            .await;

        assert!(
            matches!(result, Err(JwtBearerError::KeyNotFound(_))),
            "token referencing an unknown kid should return KeyNotFound, got: {:?}",
            result
        );
    }

    // ── extract_bearer_with_scheme ────────────────────────────────────────────

    #[test]
    fn extract_bearer_with_scheme_default_bearer_ok() {
        assert_eq!(extract_bearer_with_scheme(Some("Bearer abc"), "Bearer").unwrap(), "abc");
    }

    #[test]
    fn extract_bearer_with_scheme_custom_scheme_ok() {
        assert_eq!(extract_bearer_with_scheme(Some("Token abc"), "Token").unwrap(), "abc");
    }

    #[test]
    fn extract_bearer_with_scheme_empty_scheme_returns_raw() {
        assert_eq!(extract_bearer_with_scheme(Some(" abc "), "").unwrap(), "abc");
    }

    #[test]
    fn extract_bearer_with_scheme_wrong_scheme_is_missing() {
        assert!(matches!(extract_bearer_with_scheme(Some("Basic abc"), "Bearer"), Err(JwtBearerError::MissingToken)));
    }

    #[test]
    fn extract_bearer_with_scheme_absent_header_is_missing() {
        assert!(matches!(extract_bearer_with_scheme(None, "Bearer"), Err(JwtBearerError::MissingToken)));
    }

    #[test]
    fn extract_bearer_with_scheme_empty_token_is_missing() {
        assert!(matches!(extract_bearer_with_scheme(Some("Bearer  "), "Bearer"), Err(JwtBearerError::MissingToken)));
        assert!(matches!(extract_bearer_with_scheme(Some("   "), ""), Err(JwtBearerError::MissingToken)));
    }
}
