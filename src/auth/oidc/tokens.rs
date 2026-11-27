//! The ID token check (OpenID Connect Core 1.0 section 3.1.3.7): the signature against the
//! provider's published keys, then the issuer, audience, authorized party, expiry, issue time,
//! nonce and subject.

use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde_json::{Map, Value};

use super::config::OidcConfig;
use crate::jwt_bearer::JwksClient;
use crate::jwt_bearer::errors::JwtBearerError;

/// The JWKS cache entry the provider's keys are kept under.
const JWKS_CACHE_KEY: &str = "oidc-login";
/// Clock skew allowed on `exp` and `iat`.
const LEEWAY_SECS: u64 = 60;
/// The longest `sub` accepted.
const MAX_SUBJECT_LEN: usize = 255;

/// A verified ID token: the account it names and all its claims. Its `Debug` output names the
/// subject and claim names only, never claim values.
pub struct VerifiedIdToken {
    pub subject: String,
    pub claims: Map<String, Value>,
}

impl std::fmt::Debug for VerifiedIdToken {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("VerifiedIdToken")
            .field("subject", &self.subject)
            .field(
                "claims",
                &self
                    .claims
                    .keys()
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Why an ID token was not accepted. The detail names the check that failed, for the log; it
/// never contains the token.
#[derive(Debug)]
pub enum IdTokenFailure {
    /// The provider's published keys could not be fetched.
    KeysUnavailable(String),
    /// The token did not pass a check.
    Invalid(String),
}

impl std::fmt::Display for IdTokenFailure {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::KeysUnavailable(detail) | Self::Invalid(detail) => f.write_str(detail),
        }
    }
}

/// Verify an ID token from the token endpoint, issued for the sign-in whose nonce is
/// `expected_nonce`. A token without `kid` matches only a published key without one.
pub async fn verify_id_token(
    token: &str,
    config: &OidcConfig,
    jwks: &JwksClient,
    jwks_uri: &str,
    expected_nonce: &str,
) -> Result<VerifiedIdToken, IdTokenFailure> {
    let header = decode_header(token).map_err(|e| IdTokenFailure::Invalid(format!("unreadable header: {e}")))?;
    if !config
        .id_token_signing_algs
        .contains(&header.alg)
    {
        return Err(IdTokenFailure::Invalid(format!("algorithm {:?} is not in id_token_signing_algs", header.alg)));
    }
    let jwk = jwks
        .get_key(
            JWKS_CACHE_KEY,
            jwks_uri,
            header
                .kid
                .as_deref()
                .unwrap_or_default(),
        )
        .await
        .map_err(|e| match e {
            JwtBearerError::KeyNotFound(_) => IdTokenFailure::Invalid(format!("no published key matches: {e}")),
            _ => IdTokenFailure::KeysUnavailable(format!("signing key unavailable: {e}")),
        })?;
    if let Some(key_alg) = &jwk.alg
        && key_alg
            .parse::<Algorithm>()
            .ok()
            != Some(header.alg)
    {
        return Err(IdTokenFailure::Invalid(format!("the signing key is for {key_alg}, not {:?}", header.alg)));
    }
    if jwk
        .key_use
        .as_deref()
        .is_some_and(|key_use| key_use != "sig")
    {
        return Err(IdTokenFailure::Invalid("the signing key is not published for signatures".to_string()));
    }
    let key = crate::jwt_bearer::validator::decoding_key_from_jwk(&jwk)
        .map_err(|e| IdTokenFailure::Invalid(format!("signing key unusable: {e}")))?;

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[&config.issuer]);
    validation.set_audience(&[&config.client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.leeway = LEEWAY_SECS;
    let claims = decode::<Map<String, Value>>(token, &key, &validation)
        .map_err(|e| IdTokenFailure::Invalid(format!("{e}")))?
        .claims;

    check_claims(&claims, config, expected_nonce, chrono::Utc::now().timestamp()).map_err(IdTokenFailure::Invalid)?;
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(VerifiedIdToken { subject, claims })
}

/// The checks `jsonwebtoken` does not make: `iat`, `azp`, `nonce` and the shape of `sub`.
fn check_claims(
    claims: &Map<String, Value>,
    config: &OidcConfig,
    expected_nonce: &str,
    now: i64,
) -> Result<(), String> {
    let issued_at = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or("iat is missing")?;
    if issued_at > now + LEEWAY_SECS as i64 {
        return Err("iat is in the future".to_string());
    }

    let several_audiences = claims
        .get("aud")
        .and_then(Value::as_array)
        .is_some_and(|audiences| audiences.len() > 1);
    match claims.get("azp") {
        Some(Value::String(azp)) if azp == &config.client_id => {}
        Some(_) => return Err("azp is not this client".to_string()),
        None if several_audiences => return Err("azp is missing for a token with several audiences".to_string()),
        None => {}
    }

    if claims
        .get("nonce")
        .and_then(Value::as_str)
        != Some(expected_nonce)
    {
        return Err("nonce does not match this sign-in".to_string());
    }

    match claims
        .get("sub")
        .and_then(Value::as_str)
    {
        Some(subject) if !subject.is_empty() && subject.len() <= MAX_SUBJECT_LEN => Ok(()),
        _ => Err(format!("sub must be a string of 1 to {MAX_SUBJECT_LEN} characters")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::oidc::test_support::{
        CLIENT_ID, CLIENT_SECRET, KEY_A_KID, KEY_A_PEM, KEY_B_KID, KEY_B_PEM, StubProvider, config_for,
        id_token_claims, sign,
    };
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    async fn verify(
        provider: &StubProvider,
        token: &str,
    ) -> Result<VerifiedIdToken, String> {
        let config = config_for(&provider.issuer);
        verify_id_token(token, &config, &JwksClient::new(), &provider.jwks_uri(), "nonce-1")
            .await
            .map_err(|failure| failure.to_string())
    }

    #[tokio::test]
    async fn a_token_signed_by_the_provider_is_accepted() {
        let provider = StubProvider::start().await;
        let token = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));

        let verified = verify(&provider, &token)
            .await
            .unwrap();

        assert_eq!(verified.subject, "user-1");
        assert_eq!(verified.claims["org_id"], "org_123");
    }

    #[tokio::test]
    async fn a_token_signed_by_another_key_is_refused() {
        let provider = StubProvider::start().await;
        let forged = sign(KEY_B_PEM, Some(KEY_A_KID), &id_token_claims(&provider.issuer, "nonce-1"));

        let refused = verify(&provider, &forged)
            .await
            .unwrap_err();

        assert!(refused.contains("InvalidSignature"), "{refused}");
    }

    #[tokio::test]
    async fn a_token_with_an_unsigned_or_symmetric_algorithm_is_refused() {
        let provider = StubProvider::start().await;
        let claims = id_token_claims(&provider.issuer, "nonce-1");
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_vec(&claims).unwrap(),
        );
        let unsigned = format!("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{payload}.");
        assert!(
            verify(&provider, &unsigned)
                .await
                .unwrap_err()
                .contains("unreadable header"),
            "alg none is not even a known algorithm"
        );

        let hs256 = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(CLIENT_SECRET.as_bytes()),
        )
        .unwrap();
        assert!(
            verify(&provider, &hs256)
                .await
                .unwrap_err()
                .contains("HS256 is not in id_token_signing_algs")
        );
    }

    #[tokio::test]
    async fn an_asymmetric_algorithm_outside_the_allowed_list_is_refused() {
        let provider = StubProvider::start().await;
        let mut config = config_for(&provider.issuer);
        config.id_token_signing_algs = vec![Algorithm::EdDSA];
        let token = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));

        let refused = verify_id_token(&token, &config, &JwksClient::new(), &provider.jwks_uri(), "nonce-1")
            .await
            .unwrap_err();

        assert!(
            matches!(&refused, IdTokenFailure::Invalid(detail) if detail.contains("ES256 is not in id_token_signing_algs")),
            "{refused:?}"
        );
        assert_eq!(provider.jwks_fetches(), 0, "the algorithm is refused before any key is fetched");
    }

    #[tokio::test]
    async fn a_key_published_for_another_algorithm_is_refused() {
        let provider = StubProvider::start().await;
        provider.set_jwks(json!({ "keys": [provider.jwk_a_with_alg("ES384")] }));
        let token = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));

        let refused = verify(&provider, &token)
            .await
            .unwrap_err();

        assert!(refused.contains("the signing key is for ES384"), "{refused}");
    }

    #[tokio::test]
    async fn a_key_published_for_encryption_is_refused() {
        let provider = StubProvider::start().await;
        let mut key = provider.jwk_a_with_alg("ES256");
        key["use"] = json!("enc");
        provider.set_jwks(json!({ "keys": [key] }));
        let token = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));

        let refused = verify(&provider, &token)
            .await
            .unwrap_err();

        assert!(refused.contains("not published for signatures"), "{refused}");
    }

    #[tokio::test]
    async fn keys_that_cannot_be_fetched_are_told_apart_from_a_token_that_does_not_verify() {
        let provider = StubProvider::start().await;
        let config = config_for(&provider.issuer);
        let token = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));

        let unavailable = verify_id_token(
            &token,
            &config,
            &JwksClient::new(),
            &format!("{}/no-such-jwks", provider.issuer),
            "nonce-1",
        )
        .await
        .unwrap_err();
        assert!(matches!(unavailable, IdTokenFailure::KeysUnavailable(_)), "{unavailable:?}");

        let unknown_key = sign(KEY_B_PEM, Some(KEY_B_KID), &id_token_claims(&provider.issuer, "nonce-1"));
        let invalid = verify_id_token(&unknown_key, &config, &JwksClient::new(), &provider.jwks_uri(), "nonce-1")
            .await
            .unwrap_err();
        assert!(matches!(invalid, IdTokenFailure::Invalid(_)), "{invalid:?}");
    }

    #[tokio::test]
    async fn an_unknown_key_id_refetches_the_keys_once_so_rotation_works() {
        let provider = StubProvider::start().await;
        let config = config_for(&provider.issuer);
        let jwks = JwksClient::new();
        let first = provider.id_token(id_token_claims(&provider.issuer, "nonce-1"));
        verify_id_token(&first, &config, &jwks, &provider.jwks_uri(), "nonce-1")
            .await
            .unwrap();

        provider.rotate_to_key_b();
        let rotated = sign(KEY_B_PEM, Some(KEY_B_KID), &id_token_claims(&provider.issuer, "nonce-1"));
        verify_id_token(&rotated, &config, &jwks, &provider.jwks_uri(), "nonce-1")
            .await
            .unwrap();

        assert_eq!(provider.jwks_fetches(), 2, "one fetch at first use, one for the new key id");
    }

    #[tokio::test]
    async fn a_token_without_a_key_id_matches_only_a_key_published_without_one() {
        let provider = StubProvider::start().await;
        let unkeyed = sign(KEY_A_PEM, None, &id_token_claims(&provider.issuer, "nonce-1"));

        let refused = verify(&provider, &unkeyed)
            .await
            .unwrap_err();
        assert!(refused.contains("no published key matches"), "{refused}");

        provider.set_jwks(json!({ "keys": [provider.jwk_a_without_kid()] }));
        let verified = verify(&provider, &unkeyed)
            .await
            .unwrap();
        assert_eq!(verified.subject, "user-1");
    }

    #[test]
    fn a_verified_token_never_shows_claim_values_in_debug_output() {
        let verified = VerifiedIdToken {
            subject: "user-1".to_string(),
            claims: id_token_claims("https://idp.example.com", "nonce-1")
                .as_object()
                .unwrap()
                .clone(),
        };

        let shown = format!("{verified:?}");
        assert!(shown.contains("org_id"), "{shown}");
        assert!(!shown.contains("org_123") && !shown.contains("alice@example.com"), "{shown}");
    }

    #[tokio::test]
    async fn the_standard_claims_are_checked() {
        let provider = StubProvider::start().await;
        let now = chrono::Utc::now().timestamp();
        for (change, expected) in [
            (json!({ "iss": "https://other.example" }), "InvalidIssuer"),
            (json!({ "aud": "another-client" }), "InvalidAudience"),
            (json!({ "exp": now - 120 }), "ExpiredSignature"),
            (json!({ "sub": null }), "sub"),
        ] {
            let mut claims = id_token_claims(&provider.issuer, "nonce-1");
            for (name, value) in change.as_object().unwrap() {
                if value.is_null() {
                    claims
                        .as_object_mut()
                        .unwrap()
                        .remove(name);
                } else {
                    claims[name] = value.clone();
                }
            }
            let refused = verify(&provider, &provider.id_token(claims))
                .await
                .unwrap_err();
            assert!(refused.contains(expected), "{change}: {refused}");
        }
    }

    fn checked(change: Value) -> Result<(), String> {
        let config = config_for("https://idp.example.com");
        let mut claims = id_token_claims("https://idp.example.com", "nonce-1");
        for (name, value) in change.as_object().unwrap() {
            if value.is_null() {
                claims
                    .as_object_mut()
                    .unwrap()
                    .remove(name);
            } else {
                claims[name] = value.clone();
            }
        }
        let claims = claims
            .as_object()
            .unwrap()
            .clone();
        check_claims(&claims, &config, "nonce-1", chrono::Utc::now().timestamp())
    }

    #[test]
    fn the_nonce_must_be_this_sign_ins() {
        assert!(checked(json!({})).is_ok());
        for nonce in [json!("nonce-2"), json!(null), json!(7)] {
            assert!(
                checked(json!({ "nonce": nonce }))
                    .unwrap_err()
                    .contains("nonce"),
                "{nonce}"
            );
        }
    }

    #[test]
    fn several_audiences_need_this_client_as_the_authorized_party() {
        assert!(
            checked(json!({ "aud": [CLIENT_ID, "other"] }))
                .unwrap_err()
                .contains("azp is missing")
        );
        assert!(checked(json!({ "aud": [CLIENT_ID, "other"], "azp": CLIENT_ID })).is_ok());
        assert!(checked(json!({ "aud": [CLIENT_ID] })).is_ok(), "one audience needs no azp");
        assert!(
            checked(json!({ "azp": "other" }))
                .unwrap_err()
                .contains("azp is not this client")
        );
    }

    #[test]
    fn the_token_must_not_be_issued_in_the_future() {
        let now = chrono::Utc::now().timestamp();
        assert!(checked(json!({ "iat": now + 30 })).is_ok(), "within the leeway");
        assert!(
            checked(json!({ "iat": now + 600 }))
                .unwrap_err()
                .contains("future")
        );
        assert!(
            checked(json!({ "iat": null }))
                .unwrap_err()
                .contains("iat is missing")
        );
    }

    #[test]
    fn the_subject_must_be_a_short_non_empty_string() {
        assert!(checked(json!({ "sub": "" })).is_err());
        assert!(checked(json!({ "sub": "x".repeat(256) })).is_err());
        assert!(checked(json!({ "sub": 42 })).is_err());
        assert!(checked(json!({ "sub": "x".repeat(255) })).is_ok());
    }
}
