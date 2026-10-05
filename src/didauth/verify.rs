//! Cryptographic verification of a DID Auth challenge response.
//!
//! The caller proves control of their DID by returning a compact JWS whose
//! payload embeds the gateway-issued challenge. This module parses the JWS,
//! resolves the signing key from the DID Document, verifies the signature,
//! and validates the claim set (`challenge`, `aud`, `iat`, `exp`).
//!
//! Scope is intentionally narrow — the module owns exactly the pipeline
//! `handlers::authenticate_handler` needs. Session minting and challenge
//! bookkeeping live in `sessions.rs`.

use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::{Signature as EdSignature, Verifier as _, VerifyingKey as EdVerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use serde::Deserialize;
use serde_json::Value;

use crate::source_auth::models::DidAuthAuthConfig;

/// Maximum allowed clock skew, in seconds, when checking `iat` freshness.
pub const IAT_SKEW_SECONDS: i64 = 120;

/// Typed verification failure. Every variant carries a stable code so the HTTP
/// handler can pick a status + `problem+json` `type` slug, and the metrics
/// layer can use it as a `result` label.
#[derive(Debug, thiserror::Error)]
pub enum DidAuthVerifyError {
    #[error("challenge_response is not a valid compact JWS: {reason}")]
    MalformedJws { reason: String },

    #[error("JWS alg '{alg}' is not in the allow-list")]
    AlgorithmRejected { alg: String },

    #[error("JWS kid '{kid}' does not identify a verification method on {did}")]
    KidMismatch { kid: String, did: String },

    #[error("DID Document resolution failed for {did}: {reason}")]
    ResolverError { did: String, reason: String },

    #[error("verification method '{kid}' not found in DID Document for {did}")]
    VerificationMethodNotFound { did: String, kid: String },

    #[error("verification method '{kid}' does not expose a supported public key")]
    UnsupportedVerificationMethod { kid: String },

    #[error("JWS signature verification failed")]
    BadSignature,

    #[error("JWS payload is not a JSON object")]
    MalformedPayload,

    #[error("JWS payload challenge does not match the pending challenge")]
    ChallengeMismatch,

    #[error("JWS payload iat is missing or outside the allowed skew window")]
    IatOutOfRange,

    #[error("JWS payload is expired")]
    Expired,

    #[error("JWS payload audience does not match the configured audience")]
    AudienceMismatch,

    #[error("DID '{did}' is not in the surface allow-list")]
    DidNotAllowed { did: String },
}

impl DidAuthVerifyError {
    /// Stable machine-readable code used for metrics + `problem+json` `type`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MalformedJws { .. } => "malformed_jws",
            Self::AlgorithmRejected { .. } => "algorithm_rejected",
            Self::KidMismatch { .. } => "kid_mismatch",
            Self::ResolverError { .. } => "resolver_error",
            Self::VerificationMethodNotFound { .. } => "verification_method_not_found",
            Self::UnsupportedVerificationMethod { .. } => "unsupported_verification_method",
            Self::BadSignature => "bad_signature",
            Self::MalformedPayload => "malformed_payload",
            Self::ChallengeMismatch => "challenge_mismatch",
            Self::IatOutOfRange => "iat_out_of_range",
            Self::Expired => "expired",
            Self::AudienceMismatch => "audience_mismatch",
            Self::DidNotAllowed { .. } => "did_not_allowed",
        }
    }
}

/// A successfully verified DID Auth challenge response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDidAuth {
    pub did: String,
    pub kid: String,
    pub alg: String,
}

#[derive(Debug, Deserialize)]
struct JwsHeader {
    alg: String,
    kid: String,
}

#[derive(Debug, Deserialize)]
struct JwsPayload {
    challenge: String,
    #[serde(default)]
    aud: Option<Value>,
    iat: Option<i64>,
    exp: Option<i64>,
}

fn b64url_decode(input: &str) -> Result<Vec<u8>, DidAuthVerifyError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| DidAuthVerifyError::MalformedJws {
            reason: format!("base64url: {e}"),
        })
}

/// Public entry point.
///
/// Verifies `jws_compact` against `request_did` and `expected_challenge`,
/// using `config` for the algorithm allow-list, audience, and DID allow-list.
/// `resolver` is the shared DID resolver client (see
/// [`crate::gateways::did_cache::shared_resolver`]).
pub async fn verify_challenge_response(
    request_did: &str,
    jws_compact: &str,
    expected_challenge: &str,
    config: &DidAuthAuthConfig,
    resolver: &Arc<DIDCacheClient>,
) -> Result<VerifiedDidAuth, DidAuthVerifyError> {
    let doc_json = resolve_did_doc_as_json(resolver, request_did).await?;
    verify_challenge_response_with_doc(request_did, jws_compact, expected_challenge, config, &doc_json)
}

/// Test-friendly sibling that takes a pre-resolved DID Document instead of
/// calling out to the resolver. The full pipeline (JWS parsing, signature
/// verification, payload claim checks, allow-list enforcement) is identical
/// to the top-level `verify_challenge_response` — this variant only exists
/// so tests can supply a Document without going through the process-global
/// resolver singleton.
pub fn verify_challenge_response_with_doc(
    request_did: &str,
    jws_compact: &str,
    expected_challenge: &str,
    config: &DidAuthAuthConfig,
    doc_json: &Value,
) -> Result<VerifiedDidAuth, DidAuthVerifyError> {
    let (header, payload_bytes, signing_input, signature_bytes) = parse_compact_jws(jws_compact)?;

    let allowed_algs = config.effective_allowed_algorithms();
    if !allowed_algs
        .iter()
        .any(|a| a == &header.alg)
    {
        return Err(DidAuthVerifyError::AlgorithmRejected { alg: header.alg });
    }

    // The `kid` may be either the absolute form (`did:example:alice#key-1`)
    // or the fragment-only form (`#key-1`). In the fragment-only case the
    // DID component is empty and the identity binding is enforced later by
    // [`find_verification_method`], which searches the DID Document already
    // resolved from `request_did`. Reject only when `kid` names a *different*
    // DID than the caller claims.
    let kid_did = header
        .kid
        .split_once('#')
        .map(|(d, _)| d)
        .unwrap_or(header.kid.as_str());
    if !kid_did.is_empty() && kid_did != request_did {
        return Err(DidAuthVerifyError::KidMismatch {
            kid: header.kid.clone(),
            did: request_did.to_string(),
        });
    }

    let verification_method = find_verification_method(doc_json, &header.kid, request_did)?;

    verify_signature(
        header.alg.as_str(),
        &verification_method,
        &header.kid,
        signing_input.as_bytes(),
        &signature_bytes,
    )?;

    let payload: JwsPayload =
        serde_json::from_slice(&payload_bytes).map_err(|_| DidAuthVerifyError::MalformedPayload)?;

    if payload.challenge != expected_challenge {
        return Err(DidAuthVerifyError::ChallengeMismatch);
    }

    let now = Utc::now().timestamp();

    let iat = payload
        .iat
        .ok_or(DidAuthVerifyError::IatOutOfRange)?;
    if iat > now + IAT_SKEW_SECONDS || iat < now - IAT_SKEW_SECONDS.saturating_mul(30) {
        return Err(DidAuthVerifyError::IatOutOfRange);
    }

    if let Some(exp) = payload.exp
        && now >= exp
    {
        return Err(DidAuthVerifyError::Expired);
    }

    if let Some(expected_aud) = config.audience.as_deref() {
        let audience_ok = match &payload.aud {
            Some(Value::String(s)) => s == expected_aud,
            Some(Value::Array(arr)) => arr
                .iter()
                .any(|v| v.as_str() == Some(expected_aud)),
            _ => false,
        };
        if !audience_ok {
            return Err(DidAuthVerifyError::AudienceMismatch);
        }
    }

    if !config.allowed_dids.is_empty()
        && !config
            .allowed_dids
            .iter()
            .any(|d| d.trim() == request_did)
    {
        return Err(DidAuthVerifyError::DidNotAllowed { did: request_did.to_string() });
    }

    Ok(VerifiedDidAuth {
        did: request_did.to_string(),
        kid: header.kid,
        alg: header.alg,
    })
}

/// Split the compact JWS into `(header, payload_bytes, signing_input,
/// signature_bytes)`.
fn parse_compact_jws(jws: &str) -> Result<(JwsHeader, Vec<u8>, String, Vec<u8>), DidAuthVerifyError> {
    let mut parts = jws.split('.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| DidAuthVerifyError::MalformedJws {
            reason: "missing header".to_string(),
        })?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| DidAuthVerifyError::MalformedJws {
            reason: "missing payload".to_string(),
        })?;
    let signature_b64 = parts
        .next()
        .ok_or_else(|| DidAuthVerifyError::MalformedJws {
            reason: "missing signature".to_string(),
        })?;
    if parts.next().is_some() || header_b64.is_empty() || payload_b64.is_empty() || signature_b64.is_empty() {
        return Err(DidAuthVerifyError::MalformedJws {
            reason: "expected exactly three non-empty segments".to_string(),
        });
    }

    let header_bytes = b64url_decode(header_b64)?;
    let header: JwsHeader = serde_json::from_slice(&header_bytes).map_err(|e| DidAuthVerifyError::MalformedJws {
        reason: format!("header JSON: {e}"),
    })?;
    let payload_bytes = b64url_decode(payload_b64)?;
    let signature_bytes = b64url_decode(signature_b64)?;
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    Ok((header, payload_bytes, signing_input, signature_bytes))
}

async fn resolve_did_doc_as_json(
    resolver: &Arc<DIDCacheClient>,
    did: &str,
) -> Result<Value, DidAuthVerifyError> {
    let result = resolver
        .resolve(did)
        .await
        .map_err(|e| DidAuthVerifyError::ResolverError {
            did: did.to_string(),
            reason: e.to_string(),
        })?;
    serde_json::to_value(&result.doc).map_err(|e| DidAuthVerifyError::ResolverError {
        did: did.to_string(),
        reason: format!("serialize: {e}"),
    })
}

/// Find the verification method whose `id` matches `kid`. Accepts both the
/// absolute form (`did:web:...#key-1`) and the fragment-only form (`#key-1`).
fn find_verification_method(
    doc_json: &Value,
    kid: &str,
    did: &str,
) -> Result<Value, DidAuthVerifyError> {
    let methods = doc_json
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .ok_or_else(|| DidAuthVerifyError::VerificationMethodNotFound {
            did: did.to_string(),
            kid: kid.to_string(),
        })?;

    let fragment = kid
        .split_once('#')
        .map(|(_, f)| f);

    for method in methods {
        let Some(id) = method
            .get("id")
            .and_then(|v| v.as_str())
        else {
            continue;
        };
        if id == kid {
            return Ok(method.clone());
        }
        if let Some(frag) = fragment
            && let Some((_, id_frag)) = id.split_once('#')
            && id_frag == frag
        {
            return Ok(method.clone());
        }
    }

    Err(DidAuthVerifyError::VerificationMethodNotFound {
        did: did.to_string(),
        kid: kid.to_string(),
    })
}

fn verify_signature(
    alg: &str,
    verification_method: &Value,
    kid: &str,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), DidAuthVerifyError> {
    match alg {
        "EdDSA" => {
            let key_bytes = extract_ed25519_public_key(verification_method, kid)?;
            let key = EdVerifyingKey::from_bytes(&key_bytes).map_err(|_| DidAuthVerifyError::BadSignature)?;
            let sig = EdSignature::from_slice(signature).map_err(|_| DidAuthVerifyError::BadSignature)?;
            key.verify(signing_input, &sig)
                .map_err(|_| DidAuthVerifyError::BadSignature)
        }
        "ES256" => {
            let key = extract_p256_public_key(verification_method, kid)?;
            let sig = if signature.len() == 64 {
                P256Signature::from_slice(signature).map_err(|_| DidAuthVerifyError::BadSignature)?
            } else {
                P256Signature::from_der(signature).map_err(|_| DidAuthVerifyError::BadSignature)?
            };
            key.verify(signing_input, &sig)
                .map_err(|_| DidAuthVerifyError::BadSignature)
        }
        _ => Err(DidAuthVerifyError::AlgorithmRejected { alg: alg.to_string() }),
    }
}

fn extract_ed25519_public_key(
    method: &Value,
    kid: &str,
) -> Result<[u8; 32], DidAuthVerifyError> {
    if let Some(jwk) = method.get("publicKeyJwk")
        && let Some(x) = jwk
            .get("x")
            .and_then(|v| v.as_str())
    {
        let bytes =
            b64url_decode(x).map_err(|_| DidAuthVerifyError::UnsupportedVerificationMethod { kid: kid.to_string() })?;
        return bytes
            .try_into()
            .map_err(|_| DidAuthVerifyError::UnsupportedVerificationMethod { kid: kid.to_string() });
    }
    if let Some(multibase) = method
        .get("publicKeyMultibase")
        .and_then(|v| v.as_str())
    {
        let bytes = decode_ed25519_multibase(multibase)
            .ok_or_else(|| DidAuthVerifyError::UnsupportedVerificationMethod { kid: kid.to_string() })?;
        return bytes
            .try_into()
            .map_err(|_| DidAuthVerifyError::UnsupportedVerificationMethod { kid: kid.to_string() });
    }
    if let Some(base58) = method
        .get("publicKeyBase58")
        .and_then(|v| v.as_str())
    {
        let bytes = bs58::decode(base58)
            .into_vec()
            .map_err(|_| DidAuthVerifyError::UnsupportedVerificationMethod { kid: kid.to_string() })?;
        return bytes
            .try_into()
            .map_err(|_| DidAuthVerifyError::UnsupportedVerificationMethod { kid: kid.to_string() });
    }
    Err(DidAuthVerifyError::UnsupportedVerificationMethod { kid: kid.to_string() })
}

fn decode_ed25519_multibase(multibase: &str) -> Option<Vec<u8>> {
    let stripped = multibase.strip_prefix('z')?;
    let decoded = bs58::decode(stripped)
        .into_vec()
        .ok()?;
    if decoded.len() >= 2 && decoded[0] == 0xed && decoded[1] == 0x01 {
        Some(decoded[2..].to_vec())
    } else if decoded.len() == 32 {
        Some(decoded)
    } else {
        None
    }
}

fn extract_p256_public_key(
    method: &Value,
    kid: &str,
) -> Result<P256VerifyingKey, DidAuthVerifyError> {
    let unsupported = || DidAuthVerifyError::UnsupportedVerificationMethod { kid: kid.to_string() };
    let jwk = method
        .get("publicKeyJwk")
        .ok_or_else(unsupported)?;
    let x_b64 = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(unsupported)?;
    let y_b64 = jwk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or_else(unsupported)?;
    let x = b64url_decode(x_b64).map_err(|_| unsupported())?;
    let y = b64url_decode(y_b64).map_err(|_| unsupported())?;
    let mut uncompressed = Vec::with_capacity(1 + x.len() + y.len());
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);
    P256VerifyingKey::from_sec1_bytes(&uncompressed).map_err(|_| unsupported())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn b64u(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn make_jws(
        header: &Value,
        payload: &Value,
        signing_key: &SigningKey,
    ) -> String {
        let header_b64 = b64u(&serde_json::to_vec(header).unwrap());
        let payload_b64 = b64u(&serde_json::to_vec(payload).unwrap());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature = signing_key.sign(signing_input.as_bytes());
        format!("{}.{}", signing_input, b64u(&signature.to_bytes()))
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    fn did_doc(
        did: &str,
        kid: &str,
        verifying_key: &[u8; 32],
    ) -> Value {
        serde_json::json!({
            "id": did,
            "verificationMethod": [
                { "id": kid, "type": "Ed25519VerificationKey2020", "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": b64u(verifying_key) } }
            ]
        })
    }

    fn happy_path_config() -> DidAuthAuthConfig {
        DidAuthAuthConfig {
            extraction: crate::source_auth::models::CredentialExtraction::HttpHeader {
                field: "X-DID-Auth-Session".to_string(),
            },
            allowed_dids: vec![],
            challenge_ttl_seconds: None,
            session_ttl_seconds: None,
            audience: None,
            allowed_algorithms: vec![],
        }
    }

    #[test]
    fn parse_compact_jws_rejects_two_segments() {
        let err = parse_compact_jws("aa.bb").unwrap_err();
        assert_eq!(err.code(), "malformed_jws");
    }

    #[test]
    fn parse_compact_jws_rejects_four_segments() {
        let err = parse_compact_jws("aa.bb.cc.dd").unwrap_err();
        assert_eq!(err.code(), "malformed_jws");
    }

    #[test]
    fn decode_ed25519_multibase_z_prefix_with_codec() {
        let raw = [7u8; 32];
        let mut with_codec = vec![0xed, 0x01];
        with_codec.extend_from_slice(&raw);
        let mb = format!("z{}", bs58::encode(&with_codec).into_string());
        assert_eq!(decode_ed25519_multibase(&mb), Some(raw.to_vec()));
    }

    #[test]
    fn find_verification_method_matches_by_fragment() {
        let doc = serde_json::json!({
            "verificationMethod": [
                { "id": "did:example:abc#key-1", "type": "Ed25519VerificationKey2020", "publicKeyMultibase": "z6MkExample" }
            ]
        });
        assert!(find_verification_method(&doc, "#key-1", "did:example:abc").is_ok());
        assert!(find_verification_method(&doc, "did:example:abc#key-1", "did:example:abc").is_ok());
        assert!(find_verification_method(&doc, "#key-2", "did:example:abc").is_err());
    }

    #[test]
    fn extract_ed25519_from_publickeyjwk() {
        let raw = [5u8; 32];
        let vm = serde_json::json!({
            "id": "did:example:x#k",
            "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": b64u(&raw) }
        });
        assert_eq!(extract_ed25519_public_key(&vm, "did:example:x#k").unwrap(), raw);
    }

    #[test]
    fn verify_signature_ed25519_happy_path() {
        let sk = signing_key();
        let vk_bytes = sk.verifying_key().to_bytes();
        let vm = serde_json::json!({
            "id": "did:example:y#k",
            "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": b64u(&vk_bytes) }
        });
        let header = serde_json::json!({ "alg": "EdDSA", "kid": "did:example:y#k" });
        let payload = serde_json::json!({ "challenge": "abc", "iat": Utc::now().timestamp() });
        let jws = make_jws(&header, &payload, &sk);
        let (h, _, si, sig) = parse_compact_jws(&jws).unwrap();
        assert!(verify_signature(&h.alg, &vm, "did:example:y#k", si.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn verify_signature_ed25519_bad_signature() {
        let sk = signing_key();
        let vk_bytes = sk.verifying_key().to_bytes();
        let vm = serde_json::json!({
            "id": "did:example:z#k",
            "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": b64u(&vk_bytes) }
        });
        let header = serde_json::json!({ "alg": "EdDSA", "kid": "did:example:z#k" });
        let payload = serde_json::json!({ "challenge": "abc", "iat": Utc::now().timestamp() });
        let jws = make_jws(&header, &payload, &sk);
        let mut parts: Vec<&str> = jws.splitn(3, '.').collect();
        let mut sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .unwrap();
        *sig.last_mut().unwrap() ^= 0xff;
        let tampered = b64u(&sig);
        parts[2] = tampered.as_str();
        let jws_bad = parts.join(".");
        let (h, _, si, sig_bytes) = parse_compact_jws(&jws_bad).unwrap();
        let err = verify_signature(&h.alg, &vm, "did:example:z#k", si.as_bytes(), &sig_bytes).unwrap_err();
        assert_eq!(err.code(), "bad_signature");
    }

    // ── verify_challenge_response_with_doc pipeline coverage ─────────────

    fn did() -> &'static str {
        "did:example:alice"
    }
    fn kid() -> &'static str {
        "did:example:alice#key-1"
    }

    fn valid_jws(
        sk: &SigningKey,
        challenge: &str,
        aud: Option<&str>,
        alg_override: Option<&str>,
        kid_override: Option<&str>,
    ) -> String {
        let alg = alg_override.unwrap_or("EdDSA");
        let kid_val = kid_override.unwrap_or(kid());
        let header = serde_json::json!({ "alg": alg, "kid": kid_val });
        let now = Utc::now().timestamp();
        let mut payload = serde_json::json!({
            "challenge": challenge,
            "iat": now,
            "exp": now + 300,
        });
        if let Some(a) = aud {
            payload["aud"] = Value::String(a.to_string());
        }
        make_jws(&header, &payload, sk)
    }

    #[test]
    fn pipeline_happy_path() {
        let sk = signing_key();
        let doc = did_doc(did(), kid(), &sk.verifying_key().to_bytes());
        let jws = valid_jws(&sk, "abc", None, None, None);
        let cfg = happy_path_config();
        let verified = verify_challenge_response_with_doc(did(), &jws, "abc", &cfg, &doc).unwrap();
        assert_eq!(verified.did, did());
        assert_eq!(verified.alg, "EdDSA");
    }

    #[test]
    fn pipeline_rejects_alg_not_in_allowlist() {
        let sk = signing_key();
        let doc = did_doc(did(), kid(), &sk.verifying_key().to_bytes());
        let jws = valid_jws(&sk, "abc", None, Some("HS256"), None);
        let err = verify_challenge_response_with_doc(did(), &jws, "abc", &happy_path_config(), &doc).unwrap_err();
        assert_eq!(err.code(), "algorithm_rejected");
    }

    #[test]
    fn pipeline_rejects_kid_did_mismatch() {
        let sk = signing_key();
        let doc = did_doc(did(), kid(), &sk.verifying_key().to_bytes());
        let jws = valid_jws(&sk, "abc", None, None, Some("did:example:mallory#k"));
        let err = verify_challenge_response_with_doc(did(), &jws, "abc", &happy_path_config(), &doc).unwrap_err();
        assert_eq!(err.code(), "kid_mismatch");
    }

    /// Fragment-only `kid` values (e.g. `"#key-1"`) are DID-agnostic on the
    /// wire — the identity binding is enforced later by
    /// [`find_verification_method`], which resolves the method against the
    /// request DID's own Document. Must **not** be blocked by the
    /// `kid_did == request_did` check (which would compare the empty string
    /// to the DID and fail).
    #[test]
    fn pipeline_accepts_fragment_only_kid() {
        let sk = signing_key();
        // Register the key under the fragment-only form so
        // find_verification_method matches by fragment.
        let doc = did_doc(did(), "#key-1", &sk.verifying_key().to_bytes());
        let jws = valid_jws(&sk, "abc", None, None, Some("#key-1"));
        let verified = verify_challenge_response_with_doc(did(), &jws, "abc", &happy_path_config(), &doc).unwrap();
        assert_eq!(verified.did, did());
        assert_eq!(verified.kid, "#key-1");
    }

    #[test]
    fn pipeline_rejects_missing_verification_method() {
        let sk = signing_key();
        let doc = did_doc(did(), "did:example:alice#other-key", &sk.verifying_key().to_bytes());
        let jws = valid_jws(&sk, "abc", None, None, None);
        let err = verify_challenge_response_with_doc(did(), &jws, "abc", &happy_path_config(), &doc).unwrap_err();
        assert_eq!(err.code(), "verification_method_not_found");
    }

    #[test]
    fn pipeline_rejects_wrong_challenge() {
        let sk = signing_key();
        let doc = did_doc(did(), kid(), &sk.verifying_key().to_bytes());
        let jws = valid_jws(&sk, "abc", None, None, None);
        let err = verify_challenge_response_with_doc(did(), &jws, "different", &happy_path_config(), &doc).unwrap_err();
        assert_eq!(err.code(), "challenge_mismatch");
    }

    #[test]
    fn pipeline_rejects_bad_signature() {
        let sk = signing_key();
        let doc = did_doc(did(), kid(), &sk.verifying_key().to_bytes());
        let mut jws = valid_jws(&sk, "abc", None, None, None);
        // flip a sig byte
        {
            let mut parts: Vec<&str> = jws.splitn(3, '.').collect();
            let mut sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[2])
                .unwrap();
            sig[0] ^= 0xff;
            let tampered = b64u(&sig);
            parts[2] = tampered.as_str();
            jws = parts.join(".");
        }
        let err = verify_challenge_response_with_doc(did(), &jws, "abc", &happy_path_config(), &doc).unwrap_err();
        assert_eq!(err.code(), "bad_signature");
    }

    #[test]
    fn pipeline_rejects_expired() {
        let sk = signing_key();
        let doc = did_doc(did(), kid(), &sk.verifying_key().to_bytes());
        // Craft a payload with exp in the past.
        let now = Utc::now().timestamp();
        let header = serde_json::json!({ "alg": "EdDSA", "kid": kid() });
        let payload = serde_json::json!({ "challenge": "abc", "iat": now - 60, "exp": now - 10 });
        let jws = make_jws(&header, &payload, &sk);
        let err = verify_challenge_response_with_doc(did(), &jws, "abc", &happy_path_config(), &doc).unwrap_err();
        assert_eq!(err.code(), "expired");
    }

    #[test]
    fn pipeline_rejects_iat_in_far_future() {
        let sk = signing_key();
        let doc = did_doc(did(), kid(), &sk.verifying_key().to_bytes());
        let header = serde_json::json!({ "alg": "EdDSA", "kid": kid() });
        let payload = serde_json::json!({ "challenge": "abc", "iat": Utc::now().timestamp() + 10_000 });
        let jws = make_jws(&header, &payload, &sk);
        let err = verify_challenge_response_with_doc(did(), &jws, "abc", &happy_path_config(), &doc).unwrap_err();
        assert_eq!(err.code(), "iat_out_of_range");
    }

    #[test]
    fn pipeline_rejects_missing_iat() {
        let sk = signing_key();
        let doc = did_doc(did(), kid(), &sk.verifying_key().to_bytes());
        let header = serde_json::json!({ "alg": "EdDSA", "kid": kid() });
        let payload = serde_json::json!({ "challenge": "abc" });
        let jws = make_jws(&header, &payload, &sk);
        let err = verify_challenge_response_with_doc(did(), &jws, "abc", &happy_path_config(), &doc).unwrap_err();
        assert_eq!(err.code(), "iat_out_of_range");
    }

    #[test]
    fn pipeline_rejects_audience_mismatch() {
        let sk = signing_key();
        let doc = did_doc(did(), kid(), &sk.verifying_key().to_bytes());
        let jws = valid_jws(&sk, "abc", Some("https://example.com/other"), None, None);
        let cfg = DidAuthAuthConfig {
            audience: Some("https://gw.example.com/agent".to_string()),
            ..happy_path_config()
        };
        let err = verify_challenge_response_with_doc(did(), &jws, "abc", &cfg, &doc).unwrap_err();
        assert_eq!(err.code(), "audience_mismatch");
    }

    #[test]
    fn pipeline_accepts_audience_when_configured_and_present() {
        let sk = signing_key();
        let doc = did_doc(did(), kid(), &sk.verifying_key().to_bytes());
        let jws = valid_jws(&sk, "abc", Some("https://gw.example.com/agent"), None, None);
        let cfg = DidAuthAuthConfig {
            audience: Some("https://gw.example.com/agent".to_string()),
            ..happy_path_config()
        };
        verify_challenge_response_with_doc(did(), &jws, "abc", &cfg, &doc).unwrap();
    }

    #[test]
    fn pipeline_rejects_did_not_in_allowlist() {
        let sk = signing_key();
        let doc = did_doc(did(), kid(), &sk.verifying_key().to_bytes());
        let jws = valid_jws(&sk, "abc", None, None, None);
        let cfg = DidAuthAuthConfig {
            allowed_dids: vec!["did:example:someone-else".to_string()],
            ..happy_path_config()
        };
        let err = verify_challenge_response_with_doc(did(), &jws, "abc", &cfg, &doc).unwrap_err();
        assert_eq!(err.code(), "did_not_allowed");
    }

    #[test]
    fn pipeline_accepts_did_in_allowlist() {
        let sk = signing_key();
        let doc = did_doc(did(), kid(), &sk.verifying_key().to_bytes());
        let jws = valid_jws(&sk, "abc", None, None, None);
        let cfg = DidAuthAuthConfig {
            allowed_dids: vec![did().to_string()],
            ..happy_path_config()
        };
        verify_challenge_response_with_doc(did(), &jws, "abc", &cfg, &doc).unwrap();
    }
}
