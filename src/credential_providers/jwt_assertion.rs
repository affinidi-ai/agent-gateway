//! RFC 7523 JWT bearer assertions signed with a provider's own key.
//!
//! The provider record holds only a secret reference to the signing key. The key
//! is read from the secrets store for each grant, parsed into a `ring` key pair,
//! used to sign one assertion and dropped. Assertions are never stored or logged.

use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Upper bound for a signing key secret: an RSA 4096-bit PKCS#8 PEM or a Google
/// service account JSON key fits with room to spare.
pub const MAX_SIGNING_KEY_BYTES: usize = 16 * 1024;

/// How long an assertion is valid after it is signed.
pub const ASSERTION_LIFETIME_SECS: i64 = 300;

/// How far `iat` is set in the past, so an authorization server whose clock runs
/// slightly behind does not see an assertion issued in the future.
pub const ASSERTION_IAT_BACKDATE_SECS: i64 = 30;

const MAX_CLAIM_BYTES: usize = 1024;
const MAX_KEY_ID_BYTES: usize = 256;
const MAX_AUDIENCE_BYTES: usize = 512;

/// Signing algorithm for the assertion.
#[derive(Serialize, Deserialize, Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum JwtBearerAlgorithm {
    #[default]
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "ES256")]
    Es256,
}

impl JwtBearerAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }
}

/// Assertion settings of an `oauth2_jwt_bearer` provider.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct JwtBearerSettings {
    /// The assertion `iss`, for example a Google service account email.
    pub assertion_issuer: String,
    /// The assertion `sub`; the assertion carries no `sub` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion_subject: Option<String>,
    /// Secret holding a PKCS#8 PEM private key or a Google service account JSON key.
    pub signing_key_secret_ref: String,
    #[serde(default)]
    pub signing_algorithm: JwtBearerAlgorithm,
    /// The `kid` header; a Google service account key's `private_key_id` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// The assertion `aud`; the token endpoint when absent. Read trimmed, and a blank
    /// value reads as absent.
    #[serde(default, deserialize_with = "deserialize_audience", skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
}

fn deserialize_audience<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?
        .map(|audience| audience.trim().to_string())
        .filter(|audience| !audience.is_empty()))
}

impl JwtBearerSettings {
    pub fn subject(&self) -> Option<&str> {
        self.assertion_subject
            .as_deref()
            .filter(|subject| !subject.trim().is_empty())
    }

    pub fn audience<'a>(
        &'a self,
        token_endpoint: &'a str,
    ) -> &'a str {
        self.audience
            .as_deref()
            .unwrap_or(token_endpoint)
    }

    /// Checks the fields that need no secret: issuer, subject and key id are
    /// non-empty printable text of bounded length, the audience is 1 to 512 bytes
    /// with no whitespace or control characters, and the key reference is set.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !is_claim_text(&self.assertion_issuer, MAX_CLAIM_BYTES) {
            return Err("jwt_bearer.assertion_issuer must be non-empty printable text of at most 1024 bytes");
        }
        if self
            .assertion_subject
            .as_deref()
            .is_some_and(|subject| !is_claim_text(subject, MAX_CLAIM_BYTES))
        {
            return Err("jwt_bearer.assertion_subject must be non-empty printable text of at most 1024 bytes");
        }
        if self
            .key_id
            .as_deref()
            .is_some_and(|key_id| !is_claim_text(key_id, MAX_KEY_ID_BYTES))
        {
            return Err("jwt_bearer.key_id must be non-empty printable text of at most 256 bytes");
        }
        if self
            .audience
            .as_deref()
            .is_some_and(|audience| {
                audience.is_empty()
                    || audience.len() > MAX_AUDIENCE_BYTES
                    || audience
                        .chars()
                        .any(|c| c.is_whitespace() || c.is_control())
            })
        {
            return Err("jwt_bearer.audience must be 1 to 512 bytes with no whitespace or control characters");
        }
        if self
            .signing_key_secret_ref
            .trim()
            .is_empty()
        {
            return Err("jwt_bearer.signing_key_secret_ref is required");
        }
        Ok(())
    }
}

fn is_claim_text(
    value: &str,
    max_bytes: usize,
) -> bool {
    !value.trim().is_empty()
        && value.len() <= max_bytes
        && !value
            .chars()
            .any(char::is_control)
}

/// The non-secret view of the settings returned in provider listings.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct JwtBearerSummary {
    pub assertion_issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_subject: Option<String>,
    pub signing_algorithm: JwtBearerAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
}

impl From<&JwtBearerSettings> for JwtBearerSummary {
    fn from(settings: &JwtBearerSettings) -> Self {
        Self {
            assertion_issuer: settings
                .assertion_issuer
                .clone(),
            assertion_subject: settings
                .assertion_subject
                .clone(),
            signing_algorithm: settings.signing_algorithm,
            key_id: settings.key_id.clone(),
            audience: settings.audience.clone(),
        }
    }
}

/// Why a signing key secret was refused. The messages never include key material.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKeyError {
    #[error("signing key is larger than 16 KiB")]
    TooLarge,
    #[error("signing key must be a PKCS#8 PEM private key or a Google service account JSON key")]
    Format,
    #[error("signing key does not match the signing algorithm")]
    AlgorithmMismatch,
    #[error("assertion signing failed")]
    Signing,
}

enum KeyPair {
    Rsa(RsaKeyPair),
    Ecdsa(EcdsaKeyPair),
}

/// A parsed signing key. Its `Debug` output never shows key material.
pub struct SigningKey {
    pair: KeyPair,
    algorithm: JwtBearerAlgorithm,
    embedded_key_id: Option<String>,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("algorithm", &self.algorithm)
            .field("embedded_key_id", &self.embedded_key_id)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct ServiceAccountKey {
    private_key: String,
    #[serde(default)]
    private_key_id: Option<String>,
}

impl SigningKey {
    /// Parses a PKCS#8 PEM private key, or a Google service account JSON key whose
    /// `private_key` is one, for `algorithm`.
    pub fn parse(
        secret: &str,
        algorithm: JwtBearerAlgorithm,
    ) -> Result<Self, SigningKeyError> {
        if secret.len() > MAX_SIGNING_KEY_BYTES {
            return Err(SigningKeyError::TooLarge);
        }
        let secret = secret.trim();
        let (pem_text, embedded_key_id) = if secret.starts_with('{') {
            let account: ServiceAccountKey = serde_json::from_str(secret).map_err(|_| SigningKeyError::Format)?;
            let pem_text = Zeroizing::new(account.private_key);
            let key_id = account
                .private_key_id
                .filter(|key_id| is_claim_text(key_id, MAX_KEY_ID_BYTES));
            (pem_text, key_id)
        } else {
            (Zeroizing::new(secret.to_string()), None)
        };
        let block = pem::parse(pem_text.as_bytes()).map_err(|_| SigningKeyError::Format)?;
        if block.tag() != "PRIVATE KEY" {
            return Err(SigningKeyError::Format);
        }
        let der = Zeroizing::new(block.into_contents());
        let pair = match algorithm {
            JwtBearerAlgorithm::Rs256 => match RsaKeyPair::from_pkcs8(&der) {
                Ok(pair) => KeyPair::Rsa(pair),
                Err(_) if ecdsa_from_pkcs8(&der).is_ok() => return Err(SigningKeyError::AlgorithmMismatch),
                Err(_) => return Err(SigningKeyError::Format),
            },
            JwtBearerAlgorithm::Es256 => match ecdsa_from_pkcs8(&der) {
                Ok(pair) => KeyPair::Ecdsa(pair),
                Err(_) if RsaKeyPair::from_pkcs8(&der).is_ok() => return Err(SigningKeyError::AlgorithmMismatch),
                Err(_) => return Err(SigningKeyError::Format),
            },
        };
        Ok(Self {
            pair,
            algorithm,
            embedded_key_id,
        })
    }

    pub fn embedded_key_id(&self) -> Option<&str> {
        self.embedded_key_id
            .as_deref()
    }

    fn sign(
        &self,
        message: &[u8],
    ) -> Result<Vec<u8>, SigningKeyError> {
        let rng = SystemRandom::new();
        match &self.pair {
            KeyPair::Rsa(pair) => {
                let mut signature = vec![0; pair.public().modulus_len()];
                pair.sign(&RSA_PKCS1_SHA256, &rng, message, &mut signature)
                    .map_err(|_| SigningKeyError::Signing)?;
                Ok(signature)
            }
            KeyPair::Ecdsa(pair) => pair
                .sign(&rng, message)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| SigningKeyError::Signing),
        }
    }
}

fn ecdsa_from_pkcs8(der: &[u8]) -> Result<EcdsaKeyPair, ring::error::KeyRejected> {
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &SystemRandom::new())
}

/// The claims an assertion carries besides its timestamps and `jti`.
pub struct AssertionClaims<'a> {
    pub issuer: &'a str,
    pub subject: Option<&'a str>,
    /// The provider's audience, or the token endpoint exactly as the request is sent to it.
    pub audience: &'a str,
    pub scopes: &'a [String],
    pub key_id: Option<&'a str>,
}

/// Signs an RFC 7523 assertion: `iss`, `sub` when a subject is set, `aud`, `iat`
/// backdated by [`ASSERTION_IAT_BACKDATE_SECS`], `exp` [`ASSERTION_LIFETIME_SECS`]
/// after `now`, a random `jti`, and `scope` when scopes are requested. `now` is Unix
/// seconds.
pub fn sign_assertion(
    key: &SigningKey,
    claims: &AssertionClaims<'_>,
    now: i64,
) -> Result<Zeroizing<String>, SigningKeyError> {
    let mut header = serde_json::json!({ "alg": key.algorithm.as_str(), "typ": "JWT" });
    if let Some(key_id) = claims.key_id {
        header["kid"] = key_id.into();
    }
    let mut payload = serde_json::json!({
        "iss": claims.issuer,
        "aud": claims.audience,
        "iat": now - ASSERTION_IAT_BACKDATE_SECS,
        "exp": now + ASSERTION_LIFETIME_SECS,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    if let Some(subject) = claims.subject {
        payload["sub"] = subject.into();
    }
    if !claims.scopes.is_empty() {
        payload["scope"] = claims.scopes.join(" ").into();
    }
    let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut assertion =
        Zeroizing::new(format!("{}.{}", encoder.encode(header.to_string()), encoder.encode(payload.to_string())));
    let signature = key.sign(assertion.as_bytes())?;
    assertion.push('.');
    assertion.push_str(&encoder.encode(signature));
    Ok(assertion)
}

#[cfg(test)]
pub(crate) mod test_keys {
    use std::sync::OnceLock;

    pub(crate) fn rsa_pkcs8_pem() -> &'static str {
        static KEY: OnceLock<String> = OnceLock::new();
        KEY.get_or_init(|| {
            use rsa::pkcs8::EncodePrivateKey;
            let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("RSA test key generates");
            key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .expect("RSA test key encodes")
                .to_string()
        })
    }

    pub(crate) fn ec_pkcs8_pem() -> &'static str {
        static KEY: OnceLock<String> = OnceLock::new();
        KEY.get_or_init(|| {
            let document = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &ring::rand::SystemRandom::new(),
            )
            .expect("EC test key generates");
            pem::encode(&pem::Pem::new("PRIVATE KEY", document.as_ref().to_vec()))
        })
    }

    pub(crate) fn service_account_json(private_key_id: &str) -> String {
        serde_json::json!({
            "type": "service_account",
            "client_email": "gateway@project.iam.gserviceaccount.com",
            "private_key_id": private_key_id,
            "private_key": rsa_pkcs8_pem(),
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::test_keys::{ec_pkcs8_pem, rsa_pkcs8_pem, service_account_json};
    use super::*;
    use ring::signature::{ECDSA_P256_SHA256_FIXED, KeyPair as _, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

    const TOKEN_ENDPOINT: &str = "https://oauth2.example.com/token";

    fn settings(algorithm: JwtBearerAlgorithm) -> JwtBearerSettings {
        JwtBearerSettings {
            assertion_issuer: "gateway@project.iam.gserviceaccount.com".into(),
            assertion_subject: None,
            signing_key_secret_ref: "SIGNING_KEY".into(),
            signing_algorithm: algorithm,
            key_id: Some("key-1".into()),
            audience: None,
        }
    }

    fn decode_part(part: &str) -> serde_json::Value {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .expect("part is base64url");
        serde_json::from_slice(&bytes).expect("part is JSON")
    }

    fn split(assertion: &str) -> (serde_json::Value, serde_json::Value, Vec<u8>, String) {
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3, "a compact JWS has three parts");
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .expect("signature is base64url");
        (decode_part(parts[0]), decode_part(parts[1]), signature, format!("{}.{}", parts[0], parts[1]))
    }

    fn claims<'a>(
        settings: &'a JwtBearerSettings,
        scopes: &'a [String],
    ) -> AssertionClaims<'a> {
        AssertionClaims {
            issuer: &settings.assertion_issuer,
            subject: settings.subject(),
            audience: settings.audience(TOKEN_ENDPOINT),
            scopes,
            key_id: settings.key_id.as_deref(),
        }
    }

    #[test]
    fn test_rs256_assertion_signature_and_claims_verify() {
        let settings = settings(JwtBearerAlgorithm::Rs256);
        let key = SigningKey::parse(rsa_pkcs8_pem(), JwtBearerAlgorithm::Rs256).expect("RSA key parses");
        let scopes = vec!["https://www.googleapis.com/auth/cloud-platform".to_string(), "openid".to_string()];
        let assertion = sign_assertion(&key, &claims(&settings, &scopes), 1_800_000_000).expect("assertion signs");

        let (header, payload, signature, signing_input) = split(&assertion);
        assert_eq!(header, serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": "key-1"}));
        assert_eq!(payload["iss"], "gateway@project.iam.gserviceaccount.com");
        assert!(payload.get("sub").is_none(), "no sub claim when no subject is set");
        assert_eq!(payload["aud"], TOKEN_ENDPOINT);
        assert_eq!(payload["scope"], "https://www.googleapis.com/auth/cloud-platform openid");
        assert_eq!(payload["iat"], 1_800_000_000 - ASSERTION_IAT_BACKDATE_SECS);
        assert_eq!(payload["exp"], 1_800_000_000 + ASSERTION_LIFETIME_SECS);
        assert!(
            uuid::Uuid::parse_str(
                payload["jti"]
                    .as_str()
                    .expect("jti is a string")
            )
            .is_ok()
        );

        let block = pem::parse(rsa_pkcs8_pem()).expect("test key is PEM");
        let pair = RsaKeyPair::from_pkcs8(block.contents()).expect("test key is PKCS#8");
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pair.public_key().as_ref())
            .verify(signing_input.as_bytes(), &signature)
            .expect("signature verifies with the public key");
    }

    #[test]
    fn test_rs256_assertion_verifies_with_an_independent_jwt_library() {
        use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
        let settings = settings(JwtBearerAlgorithm::Rs256);
        let key = SigningKey::parse(rsa_pkcs8_pem(), JwtBearerAlgorithm::Rs256).expect("RSA key parses");
        let now = chrono::Utc::now().timestamp();
        let assertion = sign_assertion(&key, &claims(&settings, &[]), now).expect("assertion signs");

        let public_pem = rsa::RsaPrivateKey::from_pkcs8_pem(rsa_pkcs8_pem())
            .expect("test key parses")
            .to_public_key()
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .expect("public key encodes");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[TOKEN_ENDPOINT]);
        validation.set_issuer(&["gateway@project.iam.gserviceaccount.com"]);
        let decoded = jsonwebtoken::decode::<serde_json::Value>(
            &assertion,
            &jsonwebtoken::DecodingKey::from_rsa_pem(public_pem.as_bytes()).expect("public key loads"),
            &validation,
        )
        .expect("assertion validates");
        assert_eq!(decoded.header.kid.as_deref(), Some("key-1"));
        assert!(
            decoded
                .claims
                .get("sub")
                .is_none(),
            "no sub claim when no subject is set"
        );
        assert!(
            decoded
                .claims
                .get("scope")
                .is_none(),
            "no scope claim when no scopes are requested"
        );
    }

    #[test]
    fn test_es256_assertion_signature_is_raw_and_verifies() {
        let mut settings = settings(JwtBearerAlgorithm::Es256);
        settings.assertion_subject = Some("agent-1".into());
        let key = SigningKey::parse(ec_pkcs8_pem(), JwtBearerAlgorithm::Es256).expect("EC key parses");
        let assertion = sign_assertion(&key, &claims(&settings, &["agent.read".to_string()]), 1_800_000_000)
            .expect("assertion signs");

        let (header, payload, signature, signing_input) = split(&assertion);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "key-1");
        assert_eq!(payload["sub"], "agent-1");
        assert_eq!(payload["aud"], TOKEN_ENDPOINT);
        assert_eq!(signature.len(), 64, "ES256 signatures are raw r||s, not DER");

        let block = pem::parse(ec_pkcs8_pem()).expect("test key is PEM");
        let pair = ecdsa_from_pkcs8(block.contents()).expect("test key is PKCS#8");
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pair.public_key().as_ref())
            .verify(signing_input.as_bytes(), &signature)
            .expect("signature verifies with the public key");
    }

    #[test]
    fn test_assertion_lifetime_stays_within_one_hour() {
        const { assert!(ASSERTION_LIFETIME_SECS + ASSERTION_IAT_BACKDATE_SECS <= 3600) };
        const { assert!(ASSERTION_IAT_BACKDATE_SECS > 0) };
    }

    #[test]
    fn test_assertion_jti_is_fresh_per_signature() {
        let settings = settings(JwtBearerAlgorithm::Es256);
        let key = SigningKey::parse(ec_pkcs8_pem(), JwtBearerAlgorithm::Es256).expect("EC key parses");
        let first = split(&sign_assertion(&key, &claims(&settings, &[]), 1).expect("signs")).1;
        let second = split(&sign_assertion(&key, &claims(&settings, &[]), 1).expect("signs")).1;
        assert_ne!(first["jti"], second["jti"]);
    }

    #[test]
    fn test_assertion_without_key_id_omits_kid() {
        let mut settings = settings(JwtBearerAlgorithm::Es256);
        settings.key_id = None;
        let key = SigningKey::parse(ec_pkcs8_pem(), JwtBearerAlgorithm::Es256).expect("EC key parses");
        let header = split(&sign_assertion(&key, &claims(&settings, &[]), 1).expect("signs")).0;
        assert_eq!(header, serde_json::json!({"alg": "ES256", "typ": "JWT"}));
    }

    #[test]
    fn test_service_account_json_key_parses_with_its_key_id() {
        let key = SigningKey::parse(&service_account_json("sa-key-id"), JwtBearerAlgorithm::Rs256)
            .expect("service account key parses");
        assert_eq!(key.embedded_key_id(), Some("sa-key-id"));
        assert!(matches!(key.pair, KeyPair::Rsa(_)));
    }

    #[test]
    fn test_signing_key_parse_rejects_wrong_algorithm() {
        assert_eq!(
            SigningKey::parse(ec_pkcs8_pem(), JwtBearerAlgorithm::Rs256).map(|_| ()),
            Err(SigningKeyError::AlgorithmMismatch)
        );
        assert_eq!(
            SigningKey::parse(rsa_pkcs8_pem(), JwtBearerAlgorithm::Es256).map(|_| ()),
            Err(SigningKeyError::AlgorithmMismatch)
        );
    }

    #[test]
    fn test_signing_key_parse_rejects_bad_input() {
        let public_only = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
        let garbage_pkcs8 = pem::encode(&pem::Pem::new("PRIVATE KEY", vec![1, 2, 3]));
        let oversized = "x".repeat(MAX_SIGNING_KEY_BYTES + 1);
        for (input, expected) in [
            ("not a key", SigningKeyError::Format),
            (public_only, SigningKeyError::Format),
            (garbage_pkcs8.as_str(), SigningKeyError::Format),
            ("{\"type\":\"service_account\"}", SigningKeyError::Format),
            ("{\"private_key\":\"not a key\"}", SigningKeyError::Format),
            (oversized.as_str(), SigningKeyError::TooLarge),
        ] {
            for algorithm in [JwtBearerAlgorithm::Rs256, JwtBearerAlgorithm::Es256] {
                assert_eq!(SigningKey::parse(input, algorithm).map(|_| ()), Err(expected), "{input:?} {algorithm:?}");
            }
        }
    }

    #[test]
    fn test_signing_key_debug_and_errors_hide_key_material() {
        let key = SigningKey::parse(rsa_pkcs8_pem(), JwtBearerAlgorithm::Rs256).expect("RSA key parses");
        let debug = format!("{key:?}");
        assert!(!debug.contains("PRIVATE"));
        assert!(debug.contains("Rs256"));
        let error = SigningKey::parse(&rsa_pkcs8_pem().replace('A', "*"), JwtBearerAlgorithm::Rs256)
            .expect_err("corrupted key is refused")
            .to_string();
        assert!(!error.contains("MII"));
    }

    #[test]
    fn test_settings_validate_rejects_empty_and_control_text() {
        let valid = settings(JwtBearerAlgorithm::Rs256);
        assert_eq!(valid.validate(), Ok(()));
        let mut empty_issuer = valid.clone();
        empty_issuer.assertion_issuer = "  ".into();
        let mut control_subject = valid.clone();
        control_subject.assertion_subject = Some("a\nb".into());
        let mut long_key_id = valid.clone();
        long_key_id.key_id = Some("k".repeat(MAX_KEY_ID_BYTES + 1));
        let mut no_key = valid.clone();
        no_key.signing_key_secret_ref = String::new();
        for settings in [empty_issuer, control_subject, long_key_id, no_key] {
            assert!(settings.validate().is_err(), "{settings:?} must be refused");
        }
    }

    #[test]
    fn test_settings_subject_is_absent_unless_set() {
        let mut settings = settings(JwtBearerAlgorithm::Rs256);
        assert_eq!(settings.subject(), None);
        settings.assertion_subject = Some("  ".into());
        assert_eq!(settings.subject(), None);
        settings.assertion_subject = Some("agent-1".into());
        assert_eq!(settings.subject(), Some("agent-1"));
    }

    #[test]
    fn test_assertion_aud_is_the_audience_when_set_and_the_token_endpoint_otherwise() {
        let mut settings = settings(JwtBearerAlgorithm::Es256);
        let key = SigningKey::parse(ec_pkcs8_pem(), JwtBearerAlgorithm::Es256).expect("EC key parses");
        let payload = split(&sign_assertion(&key, &claims(&settings, &[]), 1).expect("signs")).1;
        assert_eq!(payload["aud"], TOKEN_ENDPOINT);

        settings.audience = Some("urn:example:authorization-server".into());
        settings.assertion_subject = Some("agent-1".into());
        let payload = split(&sign_assertion(&key, &claims(&settings, &[]), 1).expect("signs")).1;
        assert_eq!(payload["aud"], "urn:example:authorization-server");
        assert_eq!(payload["sub"], "agent-1");
        assert_eq!(payload["iss"], "gateway@project.iam.gserviceaccount.com");
    }

    #[test]
    fn test_settings_audience_is_trimmed_and_blank_reads_as_absent() {
        let read = |audience: serde_json::Value| -> JwtBearerSettings {
            serde_json::from_value(serde_json::json!({
                "assertion_issuer": "issuer", "signing_key_secret_ref": "KEY", "audience": audience
            }))
            .expect("settings deserialize")
        };
        assert_eq!(
            read(" https://auth.example/ ".into())
                .audience
                .as_deref(),
            Some("https://auth.example/")
        );
        assert_eq!(read("   ".into()).audience, None);
        assert_eq!(read("".into()).audience, None);
        assert_eq!(read(serde_json::Value::Null).audience, None);
    }

    #[test]
    fn test_settings_validate_checks_the_audience() {
        let mut settings = settings(JwtBearerAlgorithm::Rs256);
        for accepted in ["https://auth.example/token", "urn:example:as", &"a".repeat(MAX_AUDIENCE_BYTES)] {
            settings.audience = Some(accepted.to_string());
            assert_eq!(settings.validate(), Ok(()), "{accepted:?}");
        }
        for refused in
            [String::new(), "a b".into(), "a\u{7f}b".into(), "a\tb".into(), "a".repeat(MAX_AUDIENCE_BYTES + 1)]
        {
            settings.audience = Some(refused.clone());
            assert_eq!(
                settings.validate(),
                Err("jwt_bearer.audience must be 1 to 512 bytes with no whitespace or control characters"),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn test_stored_settings_without_audience_load_and_serialize_unchanged() {
        let stored = serde_json::json!({
            "assertion_issuer": "issuer", "assertion_subject": "agent-1",
            "signing_key_secret_ref": "KEY", "signing_algorithm": "RS256", "key_id": "key-1"
        });
        let settings: JwtBearerSettings = serde_json::from_value(stored.clone()).expect("stored settings load");
        assert_eq!(settings.audience, None);
        assert_eq!(settings.audience(TOKEN_ENDPOINT), TOKEN_ENDPOINT);
        assert_eq!(settings.validate(), Ok(()));
        assert_eq!(serde_json::to_value(&settings).expect("settings serialize"), stored);
    }

    #[test]
    fn test_settings_serde_uses_jose_algorithm_names() {
        let json = serde_json::json!({
            "assertion_issuer": "issuer", "signing_key_secret_ref": "KEY", "signing_algorithm": "ES256"
        });
        let settings: JwtBearerSettings = serde_json::from_value(json).expect("settings deserialize");
        assert_eq!(settings.signing_algorithm, JwtBearerAlgorithm::Es256);
        assert_eq!(
            serde_json::to_value(JwtBearerSummary::from(&settings)).expect("summary serializes"),
            serde_json::json!({"assertion_issuer": "issuer", "signing_algorithm": "ES256"})
        );
    }
}
