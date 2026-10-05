//! Gateway issuer attestation.
//!
//! A gateway sends fabric envelopes from a per-pairing Connection Point DID but
//! signs identity credentials with its gateway DID (`proxy_did`). The
//! attestation is a JWT signed with the gateway signing key that binds the two:
//! `iss` is the gateway DID, `sub` is the Connection Point DID the gateway
//! sends from. A peer verifies it once and stores `iss` as the Remote gateway
//! record's `issuer_did`, so identity presentations arriving from that
//! Connection Point can be required to be issued by exactly that DID.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::gateways::did_cache::DIDCache;
use crate::identity::did_keys::verification_key_from_did_document;
use crate::identity::vc_issuer::VCIssuer;

/// JOSE `typ` for the attestation, so it cannot be presented as another token.
pub const ISSUER_ATTESTATION_TYP: &str = "gateway-issuer-attestation+jwt";
/// Validity window of a freshly built attestation.
pub const ISSUER_ATTESTATION_LIFETIME_SECS: i64 = 300;
/// Tolerated clock skew for `iat` in the future.
const IAT_SKEW_SECS: i64 = 60;

const SUPPORTED_ALGS: [&str; 2] = ["EdDSA", "ES256"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuerAttestationClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub nonce: String,
    pub iat: i64,
    pub exp: i64,
}

impl IssuerAttestationClaims {
    pub fn new(
        iss: impl Into<String>,
        sub: impl Into<String>,
        aud: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        let iat = chrono::Utc::now().timestamp();
        Self {
            iss: iss.into(),
            sub: sub.into(),
            aud: aud.into(),
            nonce: nonce.into(),
            iat,
            exp: iat + ISSUER_ATTESTATION_LIFETIME_SECS,
        }
    }
}

/// What the verifier requires the attestation to say.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedAttestation<'a> {
    /// The Connection Point DID the peer sends from; this is the value the
    /// verifier stores as `Gateway.did`.
    pub sub: &'a str,
    /// The DID the attestation was addressed to (ours).
    pub aud: &'a str,
    /// The challenge the verifier issued.
    pub nonce: &'a str,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum IssuerAttestationError {
    #[error("attestation is missing")]
    Missing,
    #[error("attestation is not a well-formed JWT: {0}")]
    Malformed(String),
    #[error("attestation typ is {0:?}, expected {ISSUER_ATTESTATION_TYP:?}")]
    WrongType(String),
    #[error("attestation alg {0:?} is not supported")]
    UnsupportedAlgorithm(String),
    #[error("attestation issuer {0:?} is not a DID")]
    InvalidIssuer(String),
    #[error("attestation subject mismatch: expected {expected:?}, got {actual:?}")]
    SubjectMismatch { expected: String, actual: String },
    #[error("attestation audience mismatch: expected {expected:?}, got {actual:?}")]
    AudienceMismatch { expected: String, actual: String },
    #[error("attestation nonce does not match the challenge")]
    NonceMismatch,
    #[error("attestation has expired")]
    Expired,
    #[error("attestation is not yet valid")]
    NotYetValid,
    #[error("could not resolve the attestation issuer: {0}")]
    Resolution(String),
    #[error("attestation signature is invalid")]
    InvalidSignature,
}

#[derive(Debug, Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

struct Parsed {
    header: Header,
    claims: IssuerAttestationClaims,
    signing_input: String,
    signature: Vec<u8>,
}

/// Build an attestation for our own gateway: `iss` is the gateway DID, `sub`
/// the Connection Point DID we send from, `aud` the peer we answer, `nonce`
/// the peer's challenge.
pub async fn build_issuer_attestation(
    vc_issuer: &VCIssuer,
    sub_connection_point_did: &str,
    aud: &str,
    nonce: &str,
) -> anyhow::Result<String> {
    let claims = IssuerAttestationClaims::new(
        vc_issuer
            .get_issuer_did()
            .await?,
        sub_connection_point_did,
        aud,
        nonce,
    );
    vc_issuer
        .sign_jwt_with_gateway_key_typ(&serde_json::to_value(&claims)?, ISSUER_ATTESTATION_TYP)
        .await
}

/// Sign explicit claims with an explicit key.
#[cfg(test)]
pub(crate) fn sign_issuer_attestation(
    claims: &IssuerAttestationClaims,
    key: &ssi::jwk::JWK,
) -> anyhow::Result<String> {
    VCIssuer::sign_jwt_with_typ(&serde_json::to_value(claims)?, key, ISSUER_ATTESTATION_TYP)
}

/// Verify an attestation carried in a message body, resolving the issuer DID
/// document through the gateway's DID cache. Returns the verified issuer DID.
pub async fn verify_issuer_attestation(
    attestation: Option<&str>,
    expected: ExpectedAttestation<'_>,
    did_cache: &DIDCache,
) -> Result<String, IssuerAttestationError> {
    let parsed = parse(require_attestation(attestation)?)?;
    check_claims(&parsed, expected, chrono::Utc::now().timestamp())?;
    let (document, _) = did_cache
        .resolve_with_fallback(&parsed.claims.iss)
        .await
        .map_err(|e| IssuerAttestationError::Resolution(e.to_string()))?;
    let document = serde_json::to_value(&document).map_err(|e| IssuerAttestationError::Resolution(e.to_string()))?;
    check_signature(&parsed, &document)
}

fn require_attestation(attestation: Option<&str>) -> Result<&str, IssuerAttestationError> {
    attestation
        .filter(|jwt| !jwt.is_empty())
        .ok_or(IssuerAttestationError::Missing)
}

/// Verify an attestation against an already-resolved issuer DID document.
/// Returns the verified issuer DID.
#[cfg(test)]
pub fn verify_issuer_attestation_with_document(
    jwt: &str,
    expected: ExpectedAttestation<'_>,
    issuer_did_document: &serde_json::Value,
) -> Result<String, IssuerAttestationError> {
    let parsed = parse(jwt)?;
    check_claims(&parsed, expected, chrono::Utc::now().timestamp())?;
    check_signature(&parsed, issuer_did_document)
}

fn parse(jwt: &str) -> Result<Parsed, IssuerAttestationError> {
    let mut parts = jwt.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(IssuerAttestationError::Malformed("expected three dot-separated segments".into()));
    };

    let header: Header = decode_segment(header_b64, "header")?;
    if header.typ.as_deref() != Some(ISSUER_ATTESTATION_TYP) {
        return Err(IssuerAttestationError::WrongType(header.typ.unwrap_or_default()));
    }
    if !SUPPORTED_ALGS.contains(&header.alg.as_str()) {
        return Err(IssuerAttestationError::UnsupportedAlgorithm(header.alg));
    }

    let claims: IssuerAttestationClaims = decode_segment(payload_b64, "claims")?;
    if !claims.iss.starts_with("did:") {
        return Err(IssuerAttestationError::InvalidIssuer(claims.iss));
    }

    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|e| IssuerAttestationError::Malformed(format!("signature: {e}")))?;

    Ok(Parsed {
        header,
        claims,
        signing_input: format!("{header_b64}.{payload_b64}"),
        signature,
    })
}

fn decode_segment<T: serde::de::DeserializeOwned>(
    segment: &str,
    what: &str,
) -> Result<T, IssuerAttestationError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| IssuerAttestationError::Malformed(format!("{what}: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| IssuerAttestationError::Malformed(format!("{what}: {e}")))
}

fn check_claims(
    parsed: &Parsed,
    expected: ExpectedAttestation<'_>,
    now: i64,
) -> Result<(), IssuerAttestationError> {
    let claims = &parsed.claims;
    if claims.sub != expected.sub {
        return Err(IssuerAttestationError::SubjectMismatch {
            expected: expected.sub.to_string(),
            actual: claims.sub.clone(),
        });
    }
    if claims.aud != expected.aud {
        return Err(IssuerAttestationError::AudienceMismatch {
            expected: expected.aud.to_string(),
            actual: claims.aud.clone(),
        });
    }
    if claims.nonce != expected.nonce {
        return Err(IssuerAttestationError::NonceMismatch);
    }
    if claims.exp <= now {
        return Err(IssuerAttestationError::Expired);
    }
    if claims.iat > now + IAT_SKEW_SECS {
        return Err(IssuerAttestationError::NotYetValid);
    }
    Ok(())
}

fn check_signature(
    parsed: &Parsed,
    issuer_did_document: &serde_json::Value,
) -> Result<String, IssuerAttestationError> {
    let document_id = issuer_did_document
        .get("id")
        .and_then(|v| v.as_str());
    if document_id != Some(parsed.claims.iss.as_str()) {
        return Err(IssuerAttestationError::Resolution(format!(
            "document id {document_id:?} does not match issuer {:?}",
            parsed.claims.iss
        )));
    }

    let key = verification_key_from_did_document(issuer_did_document, parsed.header.kid.as_deref())
        .map_err(IssuerAttestationError::Resolution)?;
    if key.algorithm() != parsed.header.alg {
        return Err(IssuerAttestationError::InvalidSignature);
    }
    key.verify(
        parsed
            .signing_input
            .as_bytes(),
        &parsed.signature,
    )
    .map_err(|_| IssuerAttestationError::InvalidSignature)?;

    Ok(parsed.claims.iss.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssi::jwk::JWK;

    const GW_A: &str = "did:web:gw-a.example";
    const GW_B: &str = "did:web:gw-b.example";
    const CP_A: &str = "did:web:gw-a.example:connection-points:1111";
    const CP_B: &str = "did:web:gw-b.example:connection-points:2222";
    const NONCE: &str = "nonce-1";

    struct Issuer {
        did: &'static str,
        key: JWK,
        document: serde_json::Value,
    }

    fn issuer(did: &'static str) -> Issuer {
        let key = JWK::generate_ed25519().unwrap();
        let document = serde_json::json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#key-1"),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": serde_json::to_value(key.to_public()).unwrap(),
            }]
        });
        Issuer { did, key, document }
    }

    fn expected() -> ExpectedAttestation<'static> {
        ExpectedAttestation {
            sub: CP_A,
            aud: CP_B,
            nonce: NONCE,
        }
    }

    fn claims_for(issuer: &Issuer) -> IssuerAttestationClaims {
        IssuerAttestationClaims::new(issuer.did, CP_A, CP_B, NONCE)
    }

    fn encode(value: &serde_json::Value) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
    }

    fn raw_jwt(
        header: serde_json::Value,
        claims: &IssuerAttestationClaims,
    ) -> String {
        format!(
            "{}.{}.{}",
            encode(&header),
            encode(&serde_json::to_value(claims).unwrap()),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64])
        )
    }

    fn decode_header(jwt: &str) -> serde_json::Value {
        let header_b64 = jwt.split('.').next().unwrap();
        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(header_b64)
                .unwrap(),
        )
        .unwrap()
    }

    fn decode_claims(jwt: &str) -> IssuerAttestationClaims {
        let payload_b64 = jwt.split('.').nth(1).unwrap();
        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload_b64)
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn build_then_verify_returns_iss() {
        let a = issuer(GW_A);
        let jwt = sign_issuer_attestation(&claims_for(&a), &a.key).unwrap();

        let iss = verify_issuer_attestation_with_document(&jwt, expected(), &a.document);

        assert_eq!(iss, Ok(GW_A.to_string()));
    }

    #[test]
    fn header_typ_is_gateway_issuer_attestation() {
        let a = issuer(GW_A);
        let jwt = sign_issuer_attestation(&claims_for(&a), &a.key).unwrap();

        let header = decode_header(&jwt);

        assert_eq!(header["typ"], ISSUER_ATTESTATION_TYP);
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["kid"], "key-1");
    }

    #[test]
    fn claims_carry_sub_aud_nonce_iat_exp() {
        let a = issuer(GW_A);
        let claims = claims_for(&a);
        let jwt = sign_issuer_attestation(&claims, &a.key).unwrap();

        let decoded = decode_claims(&jwt);

        assert_eq!(decoded, claims);
        assert_eq!(decoded.iss, GW_A);
        assert_eq!(decoded.sub, CP_A);
        assert_eq!(decoded.aud, CP_B);
        assert_eq!(decoded.nonce, NONCE);
        assert_eq!(decoded.exp - decoded.iat, ISSUER_ATTESTATION_LIFETIME_SECS);
    }

    #[test]
    fn wrong_signer_same_iss_is_rejected() {
        let a = issuer(GW_A);
        let b = issuer(GW_B);
        let jwt = sign_issuer_attestation(&claims_for(&a), &b.key).unwrap();

        let result = verify_issuer_attestation_with_document(&jwt, expected(), &a.document);

        assert_eq!(result, Err(IssuerAttestationError::InvalidSignature));
    }

    #[test]
    fn sub_mismatch_is_rejected() {
        let a = issuer(GW_A);
        let jwt = sign_issuer_attestation(&claims_for(&a), &a.key).unwrap();
        let other_sub = ExpectedAttestation {
            sub: "did:web:gw-c.example:connection-points:3333",
            ..expected()
        };

        let result = verify_issuer_attestation_with_document(&jwt, other_sub, &a.document);

        assert_eq!(
            result,
            Err(IssuerAttestationError::SubjectMismatch {
                expected: other_sub.sub.to_string(),
                actual: CP_A.to_string(),
            })
        );
    }

    #[test]
    fn aud_mismatch_is_rejected() {
        let a = issuer(GW_A);
        let jwt = sign_issuer_attestation(&claims_for(&a), &a.key).unwrap();
        let other_aud = ExpectedAttestation {
            aud: "did:web:gw-c.example:connection-points:3333",
            ..expected()
        };

        let result = verify_issuer_attestation_with_document(&jwt, other_aud, &a.document);

        assert_eq!(
            result,
            Err(IssuerAttestationError::AudienceMismatch {
                expected: other_aud.aud.to_string(),
                actual: CP_B.to_string(),
            })
        );
    }

    #[test]
    fn nonce_mismatch_is_rejected() {
        let a = issuer(GW_A);
        let jwt = sign_issuer_attestation(&claims_for(&a), &a.key).unwrap();
        let other_nonce = ExpectedAttestation { nonce: "nonce-2", ..expected() };

        let result = verify_issuer_attestation_with_document(&jwt, other_nonce, &a.document);

        assert_eq!(result, Err(IssuerAttestationError::NonceMismatch));
    }

    #[test]
    fn expired_is_rejected() {
        let a = issuer(GW_A);
        let mut claims = claims_for(&a);
        claims.iat -= 1_000;
        claims.exp = claims.iat + ISSUER_ATTESTATION_LIFETIME_SECS;
        let jwt = sign_issuer_attestation(&claims, &a.key).unwrap();

        let result = verify_issuer_attestation_with_document(&jwt, expected(), &a.document);

        assert_eq!(result, Err(IssuerAttestationError::Expired));
    }

    #[test]
    fn iat_beyond_skew_is_rejected() {
        let a = issuer(GW_A);
        let mut claims = claims_for(&a);
        claims.iat += 600;
        claims.exp = claims.iat + ISSUER_ATTESTATION_LIFETIME_SECS;
        let jwt = sign_issuer_attestation(&claims, &a.key).unwrap();

        let result = verify_issuer_attestation_with_document(&jwt, expected(), &a.document);

        assert_eq!(result, Err(IssuerAttestationError::NotYetValid));
    }

    #[test]
    fn wrong_typ_is_rejected() {
        let a = issuer(GW_A);
        let jwt = raw_jwt(serde_json::json!({ "alg": "EdDSA", "typ": "JWT" }), &claims_for(&a));

        let result = verify_issuer_attestation_with_document(&jwt, expected(), &a.document);

        assert_eq!(result, Err(IssuerAttestationError::WrongType("JWT".into())));
    }

    #[test]
    fn unsupported_alg_is_rejected() {
        let a = issuer(GW_A);
        let jwt = raw_jwt(serde_json::json!({ "alg": "HS256", "typ": ISSUER_ATTESTATION_TYP }), &claims_for(&a));

        let result = verify_issuer_attestation_with_document(&jwt, expected(), &a.document);

        assert_eq!(result, Err(IssuerAttestationError::UnsupportedAlgorithm("HS256".into())));
    }

    #[test]
    fn alg_not_matching_issuer_key_is_rejected() {
        let a = issuer(GW_A);
        let jwt = raw_jwt(serde_json::json!({ "alg": "ES256", "typ": ISSUER_ATTESTATION_TYP }), &claims_for(&a));

        let result = verify_issuer_attestation_with_document(&jwt, expected(), &a.document);

        assert_eq!(result, Err(IssuerAttestationError::InvalidSignature));
    }

    #[test]
    fn non_did_iss_is_rejected() {
        let a = issuer(GW_A);
        let mut claims = claims_for(&a);
        claims.iss = "https://gw-a.example".into();
        let jwt = sign_issuer_attestation(&claims, &a.key).unwrap();

        let result = verify_issuer_attestation_with_document(&jwt, expected(), &a.document);

        assert_eq!(result, Err(IssuerAttestationError::InvalidIssuer("https://gw-a.example".into())));
    }

    #[test]
    fn document_for_a_different_did_is_rejected() {
        let a = issuer(GW_A);
        let b = issuer(GW_B);
        let jwt = sign_issuer_attestation(&claims_for(&a), &a.key).unwrap();

        let result = verify_issuer_attestation_with_document(&jwt, expected(), &b.document);

        assert!(matches!(result, Err(IssuerAttestationError::Resolution(_))), "{result:?}");
    }

    #[test]
    fn missing_or_empty_attestation_is_rejected() {
        assert_eq!(require_attestation(None), Err(IssuerAttestationError::Missing));
        assert_eq!(require_attestation(Some("")), Err(IssuerAttestationError::Missing));
        assert_eq!(require_attestation(Some("a.b.c")), Ok("a.b.c"));
    }

    #[test]
    fn malformed_token_is_rejected() {
        let a = issuer(GW_A);

        let result = verify_issuer_attestation_with_document("not.a.jwt.at.all", expected(), &a.document);

        assert!(matches!(result, Err(IssuerAttestationError::Malformed(_))), "{result:?}");
    }
}
