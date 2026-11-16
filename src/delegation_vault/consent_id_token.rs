use serde_json::Value;

use crate::jwt_bearer::JwtBearerVerifier;
use crate::jwt_bearer::errors::JwtBearerError;
use crate::jwt_bearer::models::{AudienceClaim, JwtVerificationStrategy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsentIdTokenError {
    Malformed,
    /// The strategy's JWKS could not be fetched, so the ID token was not checked.
    KeysUnavailable,
    Rejected(Rejection),
}

/// The check an ID token failed, coarse enough to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rejection {
    /// Its header, signature, key or `nbf`.
    Token,
    Issuer,
    Audience,
    Expired,
    /// The issuer and principal claim, `exp` and `nbf` a subject needs.
    Claims,
    Nonce,
    IssuedAt,
}

impl ConsentIdTokenError {
    /// A cause that names no claim value.
    pub(crate) fn cause(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::KeysUnavailable => "jwks_unavailable",
            Self::Rejected(Rejection::Token) => "token",
            Self::Rejected(Rejection::Issuer) => "issuer",
            Self::Rejected(Rejection::Audience) => "audience",
            Self::Rejected(Rejection::Expired) => "expired",
            Self::Rejected(Rejection::Claims) => "claims",
            Self::Rejected(Rejection::Nonce) => "nonce",
            Self::Rejected(Rejection::IssuedAt) => "iat",
        }
    }
}

impl From<JwtBearerError> for ConsentIdTokenError {
    fn from(error: JwtBearerError) -> Self {
        match error {
            JwtBearerError::JwksFetchFailed(_) | JwtBearerError::JwksUriBlocked => Self::KeysUnavailable,
            JwtBearerError::ExpiredToken => Self::Rejected(Rejection::Expired),
            JwtBearerError::InvalidIssuer => Self::Rejected(Rejection::Issuer),
            JwtBearerError::InvalidAudience => Self::Rejected(Rejection::Audience),
            _ => Self::Rejected(Rejection::Token),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ConsentIdTokenExpectation<'a> {
    pub client_id: &'a str,
    pub principal_claim: &'a str,
    pub nonce: &'a str,
    pub issued_at: u64,
}

pub(crate) async fn verify_consent_id_token(
    verifier: &JwtBearerVerifier,
    strategy: &JwtVerificationStrategy,
    expected: &ConsentIdTokenExpectation<'_>,
    token: &str,
    now: u64,
) -> Result<Value, ConsentIdTokenError> {
    let ConsentIdTokenExpectation {
        client_id,
        principal_claim,
        nonce,
        issued_at,
    } = *expected;
    if token.is_empty() || token.len() > 32 * 1024 || client_id.is_empty() || client_id.len() > 4096 {
        return Err(ConsentIdTokenError::Malformed);
    }
    let header = jsonwebtoken::decode_header(token).map_err(|_| ConsentIdTokenError::Rejected(Rejection::Token))?;
    if header
        .typ
        .as_deref()
        .is_some_and(|typ| typ != "JWT")
    {
        return Err(ConsentIdTokenError::Rejected(Rejection::Token));
    }
    let claims = verifier
        .validate(token, strategy, &[client_id.to_string()], AudienceClaim::Aud)
        .await?;
    crate::sts::mcp_profile::validate_subject_claims(&claims, principal_claim, now)
        .map_err(|_| ConsentIdTokenError::Rejected(Rejection::Claims))?;
    if claims
        .get("nonce")
        .and_then(Value::as_str)
        != Some(nonce)
    {
        return Err(ConsentIdTokenError::Rejected(Rejection::Nonce));
    }
    if claims
        .get("iat")
        .and_then(Value::as_u64)
        .is_none_or(|issued| issued > now.saturating_add(120) || issued.saturating_add(120) < issued_at)
    {
        return Err(ConsentIdTokenError::Rejected(Rejection::IssuedAt));
    }
    let multiple_audiences = match claims.get("aud") {
        Some(Value::String(audience)) => {
            if audience != client_id {
                return Err(ConsentIdTokenError::Rejected(Rejection::Audience));
            }
            false
        }
        Some(Value::Array(audiences)) if !audiences.is_empty() => {
            if audiences.iter().any(|value| {
                value
                    .as_str()
                    .is_none_or(str::is_empty)
            }) || !audiences
                .iter()
                .any(|value| value.as_str() == Some(client_id))
            {
                return Err(ConsentIdTokenError::Rejected(Rejection::Audience));
            }
            audiences.len() > 1
        }
        _ => return Err(ConsentIdTokenError::Rejected(Rejection::Audience)),
    };
    if (multiple_audiences || claims.get("azp").is_some())
        && claims
            .get("azp")
            .and_then(Value::as_str)
            != Some(client_id)
    {
        return Err(ConsentIdTokenError::Rejected(Rejection::Audience));
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    use serde_json::json;

    use super::*;

    const CLIENT: &str = "login-client";
    const NONCE: &str = "consent-nonce";

    struct Fixture {
        signing: ed25519_dalek::SigningKey,
        strategy: JwtVerificationStrategy,
        verifier: JwtBearerVerifier,
        now: u64,
    }

    impl Fixture {
        fn new() -> Self {
            let signing = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
            let jwks = json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": "key-1",
                "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes())}]});
            Self {
                signing,
                strategy: crate::sts::handlers::gateway_self_trust_strategy("https://identity.example/", &jwks)
                    .unwrap(),
                verifier: JwtBearerVerifier::new(std::sync::Arc::new(crate::jwt_bearer::JwksClient::new())),
                now: chrono::Utc::now().timestamp() as u64,
            }
        }

        fn claims(&self) -> Value {
            json!({"iss": self.strategy.expected_issuer, "sub": "alice", "aud": CLIENT,
                "exp": self.now + 300, "iat": self.now, "nonce": NONCE})
        }

        fn sign_with_header(
            &self,
            header: &Value,
            claims: &Value,
        ) -> String {
            let encoding = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let input = format!(
                "{}.{}",
                encoding.encode(serde_json::to_vec(header).unwrap()),
                encoding.encode(serde_json::to_vec(claims).unwrap())
            );
            let signature = encoding.encode(
                self.signing
                    .sign(input.as_bytes())
                    .to_bytes(),
            );
            format!("{input}.{signature}")
        }

        fn sign(
            &self,
            claims: &Value,
        ) -> String {
            self.sign_with_header(&json!({"alg": "EdDSA", "typ": "JWT", "kid": "key-1"}), claims)
        }

        async fn verify(
            &self,
            token: &str,
        ) -> Result<Value, ConsentIdTokenError> {
            self.verify_issued_at(token, self.now)
                .await
        }

        fn expectation(&self) -> ConsentIdTokenExpectation<'static> {
            ConsentIdTokenExpectation {
                client_id: CLIENT,
                principal_claim: "sub",
                nonce: NONCE,
                issued_at: self.now,
            }
        }

        async fn verify_issued_at(
            &self,
            token: &str,
            issued_at: u64,
        ) -> Result<Value, ConsentIdTokenError> {
            self.verify_expecting(
                token,
                ConsentIdTokenExpectation {
                    issued_at,
                    ..self.expectation()
                },
            )
            .await
        }

        async fn verify_expecting(
            &self,
            token: &str,
            expected: ConsentIdTokenExpectation<'_>,
        ) -> Result<Value, ConsentIdTokenError> {
            verify_consent_id_token(&self.verifier, &self.strategy, &expected, token, self.now).await
        }

        async fn verify_changed(
            &self,
            field: &str,
            value: Option<Value>,
        ) -> Result<Value, ConsentIdTokenError> {
            let mut claims = self.claims();
            match value {
                Some(value) => claims[field] = value,
                None => {
                    claims
                        .as_object_mut()
                        .unwrap()
                        .remove(field);
                }
            }
            self.verify(&self.sign(&claims))
                .await
        }
    }

    #[tokio::test]
    async fn an_id_token_meeting_every_check_returns_its_claims() {
        let fixture = Fixture::new();
        let claims = fixture.claims();
        assert_eq!(
            fixture
                .verify(&fixture.sign(&claims))
                .await,
            Ok(claims)
        );
    }

    #[tokio::test]
    async fn an_id_token_without_typ_is_accepted() {
        let fixture = Fixture::new();
        let claims = fixture.claims();
        let token = fixture.sign_with_header(&json!({"alg": "EdDSA", "kid": "key-1"}), &claims);
        assert_eq!(fixture.verify(&token).await, Ok(claims));
    }

    #[tokio::test]
    async fn an_id_token_of_another_typ_is_rejected() {
        let fixture = Fixture::new();
        let token =
            fixture.sign_with_header(&json!({"alg": "EdDSA", "typ": "at+jwt", "kid": "key-1"}), &fixture.claims());
        assert_eq!(fixture.verify(&token).await, Err(ConsentIdTokenError::Rejected(Rejection::Token)));
    }

    #[tokio::test]
    async fn an_empty_or_oversized_token_or_client_id_is_malformed() {
        let fixture = Fixture::new();
        let token = fixture.sign(&fixture.claims());
        let oversized = "a".repeat(32 * 1024 + 1);
        for (client_id, token) in
            [(CLIENT, ""), (CLIENT, oversized.as_str()), ("", token.as_str()), (&"c".repeat(4097), token.as_str())]
        {
            assert_eq!(
                fixture
                    .verify_expecting(
                        token,
                        ConsentIdTokenExpectation {
                            client_id,
                            ..fixture.expectation()
                        }
                    )
                    .await,
                Err(ConsentIdTokenError::Malformed),
                "client_id length {}, token length {}",
                client_id.len(),
                token.len()
            );
        }
    }

    #[tokio::test]
    async fn an_id_token_with_a_forged_signature_is_rejected() {
        let fixture = Fixture::new();
        let token = fixture.sign(&fixture.claims());
        let forged = format!(
            "{}.bad",
            token
                .rsplit_once('.')
                .unwrap()
                .0
        );
        assert_eq!(fixture.verify(&forged).await, Err(ConsentIdTokenError::Rejected(Rejection::Token)));
    }

    #[tokio::test]
    async fn an_id_token_from_another_issuer_or_without_one_is_rejected() {
        let fixture = Fixture::new();
        for (value, rejection) in [
            (Some(json!("https://other.example/")), Rejection::Issuer),
            (Some(json!("")), Rejection::Issuer),
            (None, Rejection::Issuer),
        ] {
            assert_eq!(
                fixture
                    .verify_changed("iss", value.clone())
                    .await,
                Err(ConsentIdTokenError::Rejected(rejection)),
                "{value:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_id_token_without_the_strategy_principal_claim_is_rejected() {
        let fixture = Fixture::new();
        for value in [Some(json!("")), Some(json!(7)), None] {
            assert_eq!(
                fixture
                    .verify_changed("sub", value.clone())
                    .await,
                Err(ConsentIdTokenError::Rejected(Rejection::Claims)),
                "{value:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_id_token_without_the_given_principal_claim_is_rejected() {
        let fixture = Fixture::new();
        let expected = ConsentIdTokenExpectation {
            principal_claim: "oid",
            ..fixture.expectation()
        };
        let mut claims = fixture.claims();
        assert_eq!(
            fixture
                .verify_expecting(&fixture.sign(&claims), expected)
                .await,
            Err(ConsentIdTokenError::Rejected(Rejection::Claims)),
            "sub without oid"
        );
        claims["oid"] = json!("person-1");
        assert_eq!(
            fixture
                .verify_expecting(&fixture.sign(&claims), expected)
                .await,
            Ok(claims)
        );
    }

    #[tokio::test]
    async fn an_id_token_for_another_audience_is_rejected() {
        let fixture = Fixture::new();
        for (value, rejection) in [
            (Some(json!("other-client")), Rejection::Audience),
            (Some(json!(["other-client"])), Rejection::Audience),
            (Some(json!([])), Rejection::Audience),
            (Some(json!([CLIENT, ""])), Rejection::Audience),
            (Some(json!([CLIENT, 7])), Rejection::Audience),
            (Some(json!(7)), Rejection::Audience),
            (None, Rejection::Audience),
        ] {
            assert_eq!(
                fixture
                    .verify_changed("aud", value.clone())
                    .await,
                Err(ConsentIdTokenError::Rejected(rejection)),
                "{value:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_id_token_with_an_empty_or_non_string_audience_is_rejected_even_with_azp() {
        let fixture = Fixture::new();
        for audience in [json!([CLIENT, ""]), json!([CLIENT, 7])] {
            let mut claims = fixture.claims();
            claims["aud"] = audience.clone();
            claims["azp"] = json!(CLIENT);
            assert_eq!(
                fixture
                    .verify(&fixture.sign(&claims))
                    .await,
                Err(ConsentIdTokenError::Rejected(Rejection::Audience)),
                "{audience}"
            );
        }
    }

    #[tokio::test]
    async fn an_id_token_for_several_audiences_needs_azp_naming_the_client() {
        let fixture = Fixture::new();
        let mut claims = fixture.claims();
        claims["aud"] = json!([CLIENT, "other-client"]);
        assert_eq!(
            fixture
                .verify(&fixture.sign(&claims))
                .await,
            Err(ConsentIdTokenError::Rejected(Rejection::Audience)),
            "no azp"
        );
        claims["azp"] = json!("other-client");
        assert_eq!(
            fixture
                .verify(&fixture.sign(&claims))
                .await,
            Err(ConsentIdTokenError::Rejected(Rejection::Audience)),
            "other azp"
        );
        claims["azp"] = json!(CLIENT);
        assert_eq!(
            fixture
                .verify(&fixture.sign(&claims))
                .await,
            Ok(claims)
        );
    }

    #[tokio::test]
    async fn an_id_token_whose_azp_names_another_client_is_rejected() {
        let fixture = Fixture::new();
        for value in [json!("other-client"), json!(7)] {
            assert_eq!(
                fixture
                    .verify_changed("azp", Some(value.clone()))
                    .await,
                Err(ConsentIdTokenError::Rejected(Rejection::Audience)),
                "{value}"
            );
        }
        let mut claims = fixture.claims();
        claims["azp"] = json!(CLIENT);
        assert_eq!(
            fixture
                .verify(&fixture.sign(&claims))
                .await,
            Ok(claims)
        );
    }

    #[tokio::test]
    async fn an_expired_id_token_is_rejected() {
        let fixture = Fixture::new();
        for (value, rejection) in [
            (json!(fixture.now), Rejection::Claims),
            (json!(fixture.now - 30), Rejection::Claims),
            (json!(fixture.now - 3600), Rejection::Expired),
        ] {
            assert_eq!(
                fixture
                    .verify_changed("exp", Some(value.clone()))
                    .await,
                Err(ConsentIdTokenError::Rejected(rejection)),
                "{value}"
            );
        }
    }

    #[tokio::test]
    async fn an_id_token_whose_keys_cannot_be_fetched_is_not_checked() {
        let mut fixture = Fixture::new();
        fixture.strategy.jwks_source = crate::jwt_bearer::models::JwksSource::Remote {
            jwks_uri: "https://127.0.0.1/jwks".to_string(),
        };
        let error = fixture
            .verify(&fixture.sign(&fixture.claims()))
            .await
            .unwrap_err();
        assert_eq!(error, ConsentIdTokenError::KeysUnavailable);
        assert_eq!(error.cause(), "jwks_unavailable");
    }

    #[tokio::test]
    async fn an_id_token_not_valid_yet_is_rejected() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture
                .verify_changed("nbf", Some(json!(fixture.now + 30)))
                .await,
            Err(ConsentIdTokenError::Rejected(Rejection::Claims))
        );
    }

    #[tokio::test]
    async fn an_id_token_issued_in_the_future_or_without_iat_is_rejected() {
        let fixture = Fixture::new();
        for value in [Some(json!(fixture.now + 121)), Some(json!("now")), None] {
            assert_eq!(
                fixture
                    .verify_changed("iat", value.clone())
                    .await,
                Err(ConsentIdTokenError::Rejected(Rejection::IssuedAt)),
                "{value:?}"
            );
        }
        let mut claims = fixture.claims();
        claims["iat"] = json!(fixture.now + 120);
        assert_eq!(
            fixture
                .verify(&fixture.sign(&claims))
                .await,
            Ok(claims)
        );
    }

    #[tokio::test]
    async fn an_id_token_issued_before_the_given_issue_time_less_skew_is_rejected() {
        let fixture = Fixture::new();
        let mut claims = fixture.claims();
        claims["iat"] = json!(fixture.now - 121);
        assert_eq!(
            fixture
                .verify_issued_at(&fixture.sign(&claims), fixture.now)
                .await,
            Err(ConsentIdTokenError::Rejected(Rejection::IssuedAt))
        );
        claims["iat"] = json!(fixture.now - 120);
        assert_eq!(
            fixture
                .verify_issued_at(&fixture.sign(&claims), fixture.now)
                .await,
            Ok(claims)
        );
    }

    #[tokio::test]
    async fn the_iat_lower_bound_follows_the_given_issue_time_not_now() {
        let fixture = Fixture::new();
        let issued_at = fixture.now - 300;
        let mut claims = fixture.claims();
        claims["iat"] = json!(fixture.now - 421);
        assert_eq!(
            fixture
                .verify_issued_at(&fixture.sign(&claims), issued_at)
                .await,
            Err(ConsentIdTokenError::Rejected(Rejection::IssuedAt))
        );
        claims["iat"] = json!(fixture.now - 200);
        assert_eq!(
            fixture
                .verify_issued_at(&fixture.sign(&claims), issued_at)
                .await,
            Ok(claims)
        );
    }

    #[tokio::test]
    async fn an_id_token_with_another_nonce_or_none_is_rejected() {
        let fixture = Fixture::new();
        for value in [Some(json!("other-nonce")), Some(json!(7)), None] {
            assert_eq!(
                fixture
                    .verify_changed("nonce", value.clone())
                    .await,
                Err(ConsentIdTokenError::Rejected(Rejection::Nonce)),
                "{value:?}"
            );
        }
    }
}
