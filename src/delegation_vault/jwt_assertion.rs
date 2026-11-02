//! Signed JWTs a credential provider presents to its token endpoint (RFC 7523): the
//! grant of an `oauth2_jwt_bearer` provider (section 2.1) and the client assertion of an
//! `oauth2_client_credentials_jwt_auth` provider (section 2.2). Each assertion is built
//! fresh for one token request and never stored.

use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::credential_providers::{CredentialProvider, JwtSigningAlgorithm};

/// How long an assertion is valid, well under Google's one-hour ceiling.
pub const ASSERTION_LIFETIME_SECS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AssertionError {
    #[error("signing key must be a PEM private key matching the signing algorithm")]
    InvalidSigningKey,
    #[error("certificate must be a PEM certificate")]
    InvalidCertificate,
    #[error("{0} is not configured")]
    Missing(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssertionClaims {
    pub iss: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    pub aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AssertionHeader<'a> {
    pub key_id: Option<&'a str>,
    pub certificate_pem: Option<&'a str>,
}

/// Sign `claims` with the PEM private key. The caller keeps the PEM in a zeroizing
/// buffer; neither the key nor anything derived from it appears in an error.
pub fn sign_assertion(
    key_pem: &str,
    algorithm: JwtSigningAlgorithm,
    header: AssertionHeader<'_>,
    claims: &AssertionClaims,
) -> Result<String, AssertionError> {
    let (algorithm, key) = match algorithm {
        JwtSigningAlgorithm::RS256 => (Algorithm::RS256, EncodingKey::from_rsa_pem(key_pem.as_bytes())),
        JwtSigningAlgorithm::PS256 => (Algorithm::PS256, EncodingKey::from_rsa_pem(key_pem.as_bytes())),
        JwtSigningAlgorithm::ES256 => (Algorithm::ES256, EncodingKey::from_ec_pem(key_pem.as_bytes())),
    };
    let key = key.map_err(|_| AssertionError::InvalidSigningKey)?;
    let mut jwt_header = Header::new(algorithm);
    jwt_header.typ = Some("JWT".into());
    jwt_header.kid = header
        .key_id
        .map(str::to_string);
    jwt_header.x5t_s256 = header
        .certificate_pem
        .map(certificate_thumbprint)
        .transpose()?;
    jsonwebtoken::encode(&jwt_header, claims, &key).map_err(|_| AssertionError::InvalidSigningKey)
}

/// Whether `key_pem` can sign with `algorithm`, checked by signing a probe.
pub fn check_signing_key(
    key_pem: &str,
    algorithm: JwtSigningAlgorithm,
) -> Result<(), AssertionError> {
    let probe = AssertionClaims {
        iss: "probe".into(),
        sub: None,
        aud: "probe".into(),
        scope: None,
        jti: None,
        nbf: None,
        iat: 0,
        exp: ASSERTION_LIFETIME_SECS,
    };
    sign_assertion(key_pem, algorithm, AssertionHeader::default(), &probe).map(|_| ())
}

/// The `x5t#S256` value of a PEM certificate: base64url(SHA-256(DER)), no padding.
pub fn certificate_thumbprint(certificate_pem: &str) -> Result<String, AssertionError> {
    let certificate = pem::parse(certificate_pem.trim()).map_err(|_| AssertionError::InvalidCertificate)?;
    if certificate.tag() != "CERTIFICATE" || x509_parser::parse_x509_certificate(certificate.contents()).is_err() {
        return Err(AssertionError::InvalidCertificate);
    }
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(certificate.contents())))
}

/// Claims of a JWT Bearer grant: `iss` is the configured issuer, the scopes travel in
/// the `scope` claim.
pub fn grant_assertion_claims(
    provider: &CredentialProvider,
    scopes: &[String],
    now: i64,
) -> Result<AssertionClaims, AssertionError> {
    Ok(AssertionClaims {
        iss: provider
            .jwt
            .jwt_issuer
            .clone()
            .ok_or(AssertionError::Missing("jwt_issuer"))?,
        sub: provider
            .jwt
            .jwt_subject
            .clone(),
        aud: audience(provider)?,
        scope: (!scopes.is_empty()).then(|| scopes.join(" ")),
        jti: None,
        nbf: None,
        iat: now,
        exp: now + ASSERTION_LIFETIME_SECS,
    })
}

/// Claims of a `private_key_jwt` client assertion: the client is both issuer and subject.
pub fn client_auth_assertion_claims(
    provider: &CredentialProvider,
    client_id: &str,
    now: i64,
) -> Result<AssertionClaims, AssertionError> {
    Ok(AssertionClaims {
        iss: client_id.to_string(),
        sub: Some(client_id.to_string()),
        aud: audience(provider)?,
        scope: None,
        jti: Some(uuid::Uuid::new_v4().to_string()),
        nbf: Some(now),
        iat: now,
        exp: now + ASSERTION_LIFETIME_SECS,
    })
}

fn audience(provider: &CredentialProvider) -> Result<String, AssertionError> {
    provider
        .jwt
        .jwt_audience
        .clone()
        .or_else(|| {
            provider
                .token_endpoint
                .clone()
        })
        .ok_or(AssertionError::Missing("token_endpoint"))
}

#[cfg(test)]
pub(crate) mod test_keys {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;

    pub struct TestKey {
        pub private_pem: String,
        pub public_pem: String,
    }

    pub fn rsa_pkcs8() -> TestKey {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        TestKey {
            private_pem: String::from_utf8(
                key.private_key_to_pem_pkcs8()
                    .unwrap(),
            )
            .unwrap(),
            public_pem: String::from_utf8(
                key.public_key_to_pem()
                    .unwrap(),
            )
            .unwrap(),
        }
    }

    pub fn rsa_pkcs1() -> TestKey {
        let rsa = Rsa::generate(2048).unwrap();
        TestKey {
            private_pem: String::from_utf8(
                rsa.private_key_to_pem()
                    .unwrap(),
            )
            .unwrap(),
            public_pem: String::from_utf8(
                PKey::from_rsa(rsa)
                    .unwrap()
                    .public_key_to_pem()
                    .unwrap(),
            )
            .unwrap(),
        }
    }

    pub fn ec_p256() -> TestKey {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        TestKey {
            private_pem: String::from_utf8(
                key.private_key_to_pem_pkcs8()
                    .unwrap(),
            )
            .unwrap(),
            public_pem: String::from_utf8(
                key.public_key_to_pem()
                    .unwrap(),
            )
            .unwrap(),
        }
    }

    pub fn certificate_pem() -> String {
        rcgen::generate_simple_self_signed(vec!["client.example".to_string()])
            .unwrap()
            .cert
            .pem()
    }
}

#[cfg(test)]
mod tests {
    use super::test_keys::*;
    use super::*;
    use crate::credential_providers::{CredentialProviderType, JwtAssertionSettings};
    use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};

    fn provider(provider_type: CredentialProviderType) -> CredentialProvider {
        let mut provider: CredentialProvider = serde_json::from_value(serde_json::json!({
            "id": "cp", "name": "Provider", "provider_id": "provider",
            "token_endpoint": "https://oauth2.example/token",
            "created_at": "2026-10-30T00:00:00Z", "updated_at": "2026-10-30T00:00:00Z"
        }))
        .unwrap();
        provider.provider_type = provider_type;
        provider.jwt = JwtAssertionSettings {
            jwt_issuer: Some("agent@project.iam.gserviceaccount.com".into()),
            ..Default::default()
        };
        provider
    }

    fn decoded(
        token: &str,
        public_pem: &str,
        algorithm: Algorithm,
        audience: &str,
    ) -> serde_json::Value {
        let key = match algorithm {
            Algorithm::ES256 => DecodingKey::from_ec_pem(public_pem.as_bytes()).unwrap(),
            _ => DecodingKey::from_rsa_pem(public_pem.as_bytes()).unwrap(),
        };
        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[audience]);
        validation.validate_exp = false;
        validation
            .required_spec_claims
            .clear();
        decode::<serde_json::Value>(token, &key, &validation)
            .unwrap()
            .claims
    }

    #[test]
    fn a_grant_assertion_carries_issuer_subject_scope_audience_and_a_five_minute_lifetime() {
        let key = rsa_pkcs8();
        let mut provider = provider(CredentialProviderType::OAuth2JwtBearer);
        provider.jwt.jwt_subject = Some("user@example.com".into());
        let claims = grant_assertion_claims(
            &provider,
            &["https://www.googleapis.com/auth/cloud-platform".into(), "openid".into()],
            1_000,
        )
        .unwrap();
        let token = sign_assertion(
            &key.private_pem,
            JwtSigningAlgorithm::RS256,
            AssertionHeader {
                key_id: Some("google-key-id"),
                certificate_pem: None,
            },
            &claims,
        )
        .unwrap();
        let header = decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        assert_eq!(header.typ.as_deref(), Some("JWT"));
        assert_eq!(header.kid.as_deref(), Some("google-key-id"));
        assert_eq!(header.x5t_s256, None);
        assert_eq!(
            decoded(&token, &key.public_pem, Algorithm::RS256, "https://oauth2.example/token"),
            serde_json::json!({
                "iss": "agent@project.iam.gserviceaccount.com",
                "sub": "user@example.com",
                "aud": "https://oauth2.example/token",
                "scope": "https://www.googleapis.com/auth/cloud-platform openid",
                "iat": 1_000,
                "exp": 1_300,
            })
        );
    }

    #[test]
    fn a_grant_assertion_uses_the_configured_audience_and_omits_absent_claims() {
        let key = ec_p256();
        let mut provider = provider(CredentialProviderType::OAuth2JwtBearer);
        provider.jwt.jwt_audience = Some("https://audience.example/".into());
        let claims = grant_assertion_claims(&provider, &[], 50).unwrap();
        let token =
            sign_assertion(&key.private_pem, JwtSigningAlgorithm::ES256, AssertionHeader::default(), &claims).unwrap();
        let header = decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid, None);
        assert_eq!(
            decoded(&token, &key.public_pem, Algorithm::ES256, "https://audience.example/"),
            serde_json::json!({
                "iss": "agent@project.iam.gserviceaccount.com",
                "aud": "https://audience.example/",
                "iat": 50,
                "exp": 350,
            })
        );
    }

    #[test]
    fn a_client_assertion_names_the_client_and_carries_the_certificate_thumbprint() {
        let key = rsa_pkcs1();
        let certificate = certificate_pem();
        let provider = provider(CredentialProviderType::OAuth2ClientCredentialsJwtAuth);
        let first = client_auth_assertion_claims(&provider, "client-123", 2_000).unwrap();
        let second = client_auth_assertion_claims(&provider, "client-123", 2_000).unwrap();
        assert_ne!(first.jti, second.jti);
        let token = sign_assertion(
            &key.private_pem,
            JwtSigningAlgorithm::PS256,
            AssertionHeader {
                key_id: None,
                certificate_pem: Some(&certificate),
            },
            &first,
        )
        .unwrap();
        let header = decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::PS256);
        assert_eq!(header.typ.as_deref(), Some("JWT"));
        let der = pem::parse(&certificate).unwrap();
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(der.contents()));
        assert_eq!(header.x5t_s256.as_deref(), Some(expected.as_str()));
        let claims = decoded(&token, &key.public_pem, Algorithm::PS256, "https://oauth2.example/token");
        assert_eq!(claims["iss"], "client-123");
        assert_eq!(claims["sub"], "client-123");
        assert_eq!(claims["aud"], "https://oauth2.example/token");
        assert_eq!(claims["jti"], first.jti.unwrap().as_str());
        assert_eq!(claims["nbf"], 2_000);
        assert_eq!(claims["iat"], 2_000);
        assert_eq!(claims["exp"], 2_300);
        assert!(claims.get("scope").is_none());
    }

    #[test]
    fn a_wrong_key_or_certificate_is_a_typed_error_that_never_echoes_the_material() {
        let rsa = rsa_pkcs8();
        let ec = ec_p256();
        assert_eq!(check_signing_key(&rsa.private_pem, JwtSigningAlgorithm::RS256), Ok(()));
        assert_eq!(check_signing_key(&rsa.private_pem, JwtSigningAlgorithm::PS256), Ok(()));
        assert_eq!(check_signing_key(&ec.private_pem, JwtSigningAlgorithm::ES256), Ok(()));
        for (pem, algorithm) in [
            (ec.private_pem.as_str(), JwtSigningAlgorithm::RS256),
            (rsa.private_pem.as_str(), JwtSigningAlgorithm::ES256),
            (rsa.public_pem.as_str(), JwtSigningAlgorithm::RS256),
            ("key-secret-marker", JwtSigningAlgorithm::RS256),
            ("{\"kty\":\"RSA\",\"d\":\"key-secret-marker\"}", JwtSigningAlgorithm::RS256),
        ] {
            let error = check_signing_key(pem, algorithm).unwrap_err();
            assert_eq!(error, AssertionError::InvalidSigningKey);
            assert!(
                !error
                    .to_string()
                    .contains("key-secret-marker")
            );
            assert!(!format!("{error:?}").contains("PRIVATE"));
        }
        assert_eq!(certificate_thumbprint(&rsa.private_pem), Err(AssertionError::InvalidCertificate));
        assert_eq!(
            certificate_thumbprint("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"),
            Err(AssertionError::InvalidCertificate)
        );
        let claims =
            client_auth_assertion_claims(&provider(CredentialProviderType::OAuth2ClientCredentialsJwtAuth), "c", 0)
                .unwrap();
        assert_eq!(
            sign_assertion(
                &rsa.private_pem,
                JwtSigningAlgorithm::PS256,
                AssertionHeader {
                    key_id: None,
                    certificate_pem: Some("not a certificate"),
                },
                &claims,
            ),
            Err(AssertionError::InvalidCertificate)
        );
    }

    #[test]
    fn claims_need_an_issuer_and_an_audience() {
        let mut provider = provider(CredentialProviderType::OAuth2JwtBearer);
        provider.jwt.jwt_issuer = None;
        assert_eq!(grant_assertion_claims(&provider, &[], 0), Err(AssertionError::Missing("jwt_issuer")));
        provider.token_endpoint = None;
        assert_eq!(
            client_auth_assertion_claims(&provider, "client", 0),
            Err(AssertionError::Missing("token_endpoint"))
        );
    }
}
