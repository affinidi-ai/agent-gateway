use axum::{Json, extract::State, http::StatusCode};
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

use crate::identity::did_keys::{DidVerificationKey, verification_key_from_did_document, verification_key_from_jwk};
use crate::identity::state::IdentityApiState;

#[derive(Debug, Deserialize)]
pub struct VerifyJwtRequest {
    pub token: String,
    pub expected_audience: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyJwtResponse {
    pub valid: bool,
    pub token_type: String,
    pub issuer_did: Option<String>,
    pub claims: Option<serde_json::Value>,
    pub error: Option<String>,
    /// For SD-JWT-VC: issuer JWT claims
    pub issuer_claims: Option<serde_json::Value>,
    /// For SD-JWT-VC: key-binding JWT claims
    pub key_binding_claims: Option<serde_json::Value>,
}

pub async fn verify_jwt(
    State(state): State<IdentityApiState>,
    Json(request): Json<VerifyJwtRequest>,
) -> Result<Json<VerifyJwtResponse>, (StatusCode, String)> {
    let token_type = if request.token.contains('~') {
        "sd-jwt-vc"
    } else {
        "jwt"
    };

    info!(
        token_type = token_type,
        token_len = request.token.len(),
        expected_audience = ?request.expected_audience,
        "agents-api: verify-jwt request"
    );

    if token_type == "sd-jwt-vc" {
        info!("Processing SD-JWT-VC verification");
        return verify_sd_jwt_vc(&state, &request).await;
    }

    // Use unified verification with DID resolution
    let result = verify_jwt_common(
        &request.token,
        token_type,
        VerificationMode::WithDid {
            state: &state,
            expected_audience: request
                .expected_audience
                .as_deref(),
        },
    )
    .await?;

    Ok(Json(result))
}

fn decode_jwt_part(part: &str) -> Result<serde_json::Value, String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("JSON parse error: {}", e))
}

async fn get_public_key_for_did(
    state: &IdentityApiState,
    did: &str,
    kid: Option<&str>,
) -> Result<DidVerificationKey, String> {
    if let Ok(Some(record)) = state
        .vc_issuer
        .get_identity_store()
        .find_by_did(did)
        .await
        && let Some(ref private_key_json) = record.private_key
    {
        return verification_key_from_jwk(private_key_json);
    }

    let resolver = crate::gateways::did_cache::shared_resolver();

    let resolution_result = resolver
        .resolve(did)
        .await
        .map_err(|e| format!("DID resolution failed: {}", e))?;

    let doc_json =
        serde_json::to_value(&resolution_result.doc).map_err(|e| format!("Failed to serialize DID document: {}", e))?;

    verification_key_from_did_document(&doc_json, kid)
}

/// Verify SD-JWT-VC (format: issuer-jwt~key-binding-jwt)
async fn verify_sd_jwt_vc(
    state: &IdentityApiState,
    request: &VerifyJwtRequest,
) -> Result<Json<VerifyJwtResponse>, (StatusCode, String)> {
    // Split on tilde separator
    let parts: Vec<&str> = request
        .token
        .split('~')
        .collect();
    if parts.len() != 2 {
        return Ok(Json(VerifyJwtResponse {
            valid: false,
            token_type: "sd-jwt-vc".to_string(),
            issuer_did: None,
            claims: None,
            error: Some(format!("Invalid SD-JWT-VC format: expected 2 parts separated by ~, got {}", parts.len())),
            issuer_claims: None,
            key_binding_claims: None,
        }));
    }

    let issuer_jwt = parts[0];
    let kb_jwt = parts[1];

    info!("Verifying SD-JWT-VC: issuer JWT + key-binding JWT");

    // 1. Verify issuer JWT (signed by Credentials Provider)
    let issuer_result = verify_jwt_internal(state, issuer_jwt, None).await?;
    if !issuer_result.valid {
        return Ok(Json(VerifyJwtResponse {
            valid: false,
            token_type: "sd-jwt-vc".to_string(),
            issuer_did: issuer_result.issuer_did,
            claims: None,
            error: Some(format!(
                "Issuer JWT verification failed: {}",
                issuer_result
                    .error
                    .unwrap_or_default()
            )),
            issuer_claims: issuer_result.claims,
            key_binding_claims: None,
        }));
    }

    let issuer_claims = issuer_result
        .claims
        .clone()
        .unwrap();
    let issuer_did = issuer_result
        .issuer_did
        .clone()
        .unwrap();

    info!(issuer_did = %issuer_did, "✓ Issuer JWT verified");

    // 2. Extract cnf.jwk (user device public key) from issuer claims
    let user_jwk = issuer_claims
        .get("cnf")
        .and_then(|cnf| cnf.get("jwk"))
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Issuer JWT missing cnf.jwk claim".to_string()))?;

    info!("Extracted user device public key from cnf.jwk");

    // 3. Verify key-binding JWT (signed by user device)
    let kb_result = verify_jwt_with_jwk(kb_jwt, user_jwk).await?;
    if !kb_result.valid {
        return Ok(Json(VerifyJwtResponse {
            valid: false,
            token_type: "sd-jwt-vc".to_string(),
            issuer_did: Some(issuer_did),
            claims: None,
            error: Some(format!(
                "Key-binding JWT verification failed: {}",
                kb_result
                    .error
                    .unwrap_or_default()
            )),
            issuer_claims: Some(issuer_claims),
            key_binding_claims: kb_result.claims,
        }));
    }

    let kb_claims = kb_result
        .claims
        .clone()
        .unwrap();

    info!("✓ Key-binding JWT verified");

    // 4. Validate sd_hash matches issuer JWT
    let sd_hash = kb_claims
        .get("sd_hash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Key-binding JWT missing sd_hash claim".to_string()))?;

    // Compute SHA256 hash of issuer JWT
    let mut hasher = Sha256::new();
    hasher.update(issuer_jwt.as_bytes());
    let computed_hash = hasher.finalize();
    let computed_hash_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(computed_hash);

    if sd_hash != computed_hash_b64 {
        return Ok(Json(VerifyJwtResponse {
            valid: false,
            token_type: "sd-jwt-vc".to_string(),
            issuer_did: Some(issuer_did),
            claims: None,
            error: Some(format!("sd_hash mismatch: expected {}, got {}", computed_hash_b64, sd_hash)),
            issuer_claims: Some(issuer_claims),
            key_binding_claims: Some(kb_claims),
        }));
    }

    info!("✓ sd_hash validated");

    // 5. Optionally validate transaction_data hashes
    if let Some(transaction_data) = kb_claims.get("transaction_data") {
        info!("Found transaction_data in key-binding JWT: {:?}", transaction_data);
        // Lenient validation: just check that it exists and is an array
        if !transaction_data.is_array() {
            warn!("transaction_data is not an array");
        }
    }

    // All validations passed
    info!(issuer_did = %issuer_did, "✓ SD-JWT-VC verification successful");

    Ok(Json(VerifyJwtResponse {
        valid: true,
        token_type: "sd-jwt-vc".to_string(),
        issuer_did: Some(issuer_did),
        claims: None,
        error: None,
        issuer_claims: Some(issuer_claims),
        key_binding_claims: Some(kb_claims),
    }))
}

/// Verify JWT using internal logic (for issuer JWT in SD-JWT-VC)
async fn verify_jwt_internal(
    state: &IdentityApiState,
    jwt: &str,
    expected_audience: Option<&str>,
) -> Result<VerifyJwtResponse, (StatusCode, String)> {
    verify_jwt_common(jwt, "jwt", VerificationMode::WithDid { state, expected_audience }).await
}

/// Verify JWT using a provided JWK public key (for key-binding JWT)
async fn verify_jwt_with_jwk(
    jwt: &str,
    jwk: &serde_json::Value,
) -> Result<VerifyJwtResponse, (StatusCode, String)> {
    verify_jwt_common(jwt, "jwt", VerificationMode::WithJwk { jwk }).await
}

/// Verification mode: either resolve DID or use provided JWK
enum VerificationMode<'a> {
    WithDid { state: &'a IdentityApiState, expected_audience: Option<&'a str> },
    WithJwk { jwk: &'a serde_json::Value },
}

/// Unified JWT verification function
async fn verify_jwt_common(
    jwt: &str,
    token_type: &str,
    mode: VerificationMode<'_>,
) -> Result<VerifyJwtResponse, (StatusCode, String)> {
    // Parse JWT
    let parsed = match ParsedJwt::parse(jwt) {
        Ok(p) => p,
        Err(e) => return error_response(token_type, e),
    };

    // Validate algorithm
    let alg = parsed.algorithm();
    let expected_algs = match &mode {
        VerificationMode::WithDid { .. } => vec!["EdDSA"],
        VerificationMode::WithJwk { .. } => vec!["ES256", "EdDSA"],
    };

    if !expected_algs.contains(&alg) {
        return error_response_with_claims(
            token_type,
            None,
            Some(parsed.payload.clone()),
            format!("Unsupported algorithm: {}. Expected {:?}", alg, expected_algs),
        );
    }

    // Validate claims
    let validator = ClaimsValidator::new(&parsed.payload);

    let issuer = match mode {
        VerificationMode::WithDid { .. } => match validator.validate_issuer() {
            Ok(iss) => iss,
            Err(e) => return error_response(token_type, e),
        },
        VerificationMode::WithJwk { .. } => String::new(),
    };

    if let Err(e) = validator.validate_expiration() {
        return error_response_with_claims(
            token_type,
            if issuer.is_empty() {
                None
            } else {
                Some(issuer)
            },
            Some(parsed.payload.clone()),
            e,
        );
    }

    if let VerificationMode::WithDid { expected_audience, .. } = mode
        && let Some(aud) = expected_audience
        && let Err(e) = validator.validate_audience(aud)
    {
        return error_response_with_claims(token_type, Some(issuer.clone()), Some(parsed.payload.clone()), e);
    }

    // Get verifier
    let verifier = match mode {
        VerificationMode::WithDid { state, .. } => {
            match SignatureVerifier::from_did(state, &issuer, parsed.kid()).await {
                Ok(v) => v,
                Err(e) => {
                    error!(issuer_did = %issuer, error = %e, "Failed to resolve public key");
                    return error_response_with_claims(
                        token_type,
                        Some(issuer.clone()),
                        Some(parsed.payload.clone()),
                        format!("Failed to resolve issuer public key: {}", e),
                    );
                }
            }
        }
        VerificationMode::WithJwk { jwk } => SignatureVerifier::from_jwk(jwk, alg)?,
    };

    // Verify signature
    if let Err(e) = verifier.verify(
        parsed
            .signing_input()
            .as_bytes(),
        &parsed.signature_b64,
    ) {
        warn!(error = %e, "Signature verification failed");
        return error_response_with_claims(
            token_type,
            if issuer.is_empty() {
                None
            } else {
                Some(issuer.clone())
            },
            Some(parsed.payload.clone()),
            e,
        );
    }

    // Success
    info!(issuer_did = %issuer, "JWT signature verified successfully");
    success_response(token_type, issuer, parsed.payload.clone())
}

/// Helper functions for building VerifyJwtResponse
fn error_response(
    token_type: &str,
    error: impl Into<String>,
) -> Result<VerifyJwtResponse, (StatusCode, String)> {
    Ok(VerifyJwtResponse {
        valid: false,
        token_type: token_type.to_string(),
        issuer_did: None,
        claims: None,
        error: Some(error.into()),
        issuer_claims: None,
        key_binding_claims: None,
    })
}

fn error_response_with_claims(
    token_type: &str,
    issuer: Option<String>,
    claims: Option<serde_json::Value>,
    error: impl Into<String>,
) -> Result<VerifyJwtResponse, (StatusCode, String)> {
    Ok(VerifyJwtResponse {
        valid: false,
        token_type: token_type.to_string(),
        issuer_did: issuer,
        claims,
        error: Some(error.into()),
        issuer_claims: None,
        key_binding_claims: None,
    })
}

fn success_response(
    token_type: &str,
    issuer: String,
    claims: serde_json::Value,
) -> Result<VerifyJwtResponse, (StatusCode, String)> {
    Ok(VerifyJwtResponse {
        valid: true,
        token_type: token_type.to_string(),
        issuer_did: if issuer.is_empty() {
            None
        } else {
            Some(issuer)
        },
        claims: Some(claims),
        error: None,
        issuer_claims: None,
        key_binding_claims: None,
    })
}

/// Parsed JWT with decoded parts
struct ParsedJwt {
    header: serde_json::Value,
    payload: serde_json::Value,
    header_b64: String,
    payload_b64: String,
    signature_b64: String,
}

impl ParsedJwt {
    fn parse(jwt: &str) -> Result<Self, String> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid JWT format: expected 3 parts".to_string());
        }

        Ok(Self {
            header: decode_jwt_part(parts[0])?,
            payload: decode_jwt_part(parts[1])?,
            header_b64: parts[0].to_string(),
            payload_b64: parts[1].to_string(),
            signature_b64: parts[2].to_string(),
        })
    }

    fn algorithm(&self) -> &str {
        self.header
            .get("alg")
            .and_then(|a| a.as_str())
            .unwrap_or("")
    }

    fn _issuer(&self) -> Option<&str> {
        self.payload
            .get("iss")
            .and_then(|i| i.as_str())
    }

    fn kid(&self) -> Option<&str> {
        self.header
            .get("kid")
            .and_then(|k| k.as_str())
    }

    fn signing_input(&self) -> String {
        format!("{}.{}", self.header_b64, self.payload_b64)
    }
}

/// Claims validator for common JWT claim validations
struct ClaimsValidator<'a> {
    payload: &'a serde_json::Value,
}

impl<'a> ClaimsValidator<'a> {
    fn new(payload: &'a serde_json::Value) -> Self {
        Self { payload }
    }

    fn validate_issuer(&self) -> Result<String, String> {
        self.payload
            .get("iss")
            .and_then(|i| i.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "Missing 'iss' claim in JWT payload".to_string())
    }

    fn validate_expiration(&self) -> Result<(), String> {
        if let Some(exp) = self
            .payload
            .get("exp")
            .and_then(|e| e.as_i64())
        {
            let now = Utc::now().timestamp();
            if now > exp {
                return Err("JWT has expired".to_string());
            }
        }
        Ok(())
    }

    fn validate_audience(
        &self,
        expected: &str,
    ) -> Result<(), String> {
        let aud_valid = match self.payload.get("aud") {
            Some(serde_json::Value::String(aud)) => aud == expected,
            Some(serde_json::Value::Array(auds)) => auds
                .iter()
                .any(|a| a.as_str() == Some(expected)),
            _ => false,
        };

        if !aud_valid {
            return Err(format!("Audience mismatch: expected '{}'", expected));
        }
        Ok(())
    }
}

/// Unified signature verifier for different algorithms
enum SignatureVerifier {
    EdDSA(VerifyingKey),
    ES256(P256VerifyingKey),
}

impl SignatureVerifier {
    async fn from_did(
        state: &IdentityApiState,
        did: &str,
        kid: Option<&str>,
    ) -> Result<Self, String> {
        Ok(match get_public_key_for_did(state, did, kid).await? {
            DidVerificationKey::Ed25519(key) => Self::EdDSA(key),
            DidVerificationKey::P256(key) => Self::ES256(key),
        })
    }

    fn from_jwk(
        jwk: &serde_json::Value,
        alg: &str,
    ) -> Result<Self, (StatusCode, String)> {
        match alg {
            "ES256" => {
                let x_b64 = jwk
                    .get("x")
                    .and_then(|v| v.as_str())
                    .ok_or((StatusCode::BAD_REQUEST, "JWK missing 'x' coordinate".to_string()))?;
                let y_b64 = jwk
                    .get("y")
                    .and_then(|v| v.as_str())
                    .ok_or((StatusCode::BAD_REQUEST, "JWK missing 'y' coordinate".to_string()))?;

                let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(x_b64)
                    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to decode x: {}", e)))?;
                let y_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(y_b64)
                    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to decode y: {}", e)))?;

                let mut uncompressed_key = vec![0x04];
                uncompressed_key.extend_from_slice(&x_bytes);
                uncompressed_key.extend_from_slice(&y_bytes);

                let key = P256VerifyingKey::from_sec1_bytes(&uncompressed_key)
                    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid P-256 key: {}", e)))?;

                Ok(Self::ES256(key))
            }
            "EdDSA" => Err((StatusCode::NOT_IMPLEMENTED, "EdDSA with JWK not implemented".to_string())),
            _ => Err((StatusCode::BAD_REQUEST, format!("Unsupported algorithm: {}", alg))),
        }
    }

    fn verify(
        &self,
        message: &[u8],
        signature_b64: &str,
    ) -> Result<(), String> {
        let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|e| format!("Failed to decode signature: {}", e))?;

        match self {
            Self::EdDSA(key) => {
                let signature =
                    Signature::from_slice(&signature_bytes).map_err(|e| format!("Invalid EdDSA signature: {}", e))?;
                key.verify(message, &signature)
                    .map_err(|_| "EdDSA signature verification failed".to_string())
            }
            Self::ES256(key) => {
                let signature = if signature_bytes.len() == 64 {
                    P256Signature::from_slice(&signature_bytes)
                } else {
                    P256Signature::from_der(&signature_bytes)
                        .or_else(|_| P256Signature::try_from(signature_bytes.as_slice()))
                }
                .map_err(|e| format!("Invalid ES256 signature: {}", e))?;

                key.verify(message, &signature)
                    .map_err(|_| "ES256 signature verification failed".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const DID: &str = "did:web:agent.example.com";

    fn b64u(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn jwk_method(
        fragment: &str,
        key: &SigningKey,
    ) -> serde_json::Value {
        json!({
            "id": format!("{}#{}", DID, fragment),
            "type": "JsonWebKey2020",
            "controller": DID,
            "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": b64u(key.verifying_key().as_bytes()) }
        })
    }

    fn two_key_document() -> Vec<serde_json::Value> {
        vec![jwk_method("key-1", &key(1)), jwk_method("key-2", &key(2))]
    }

    fn signed_jwt(
        kid: Option<&str>,
        key: &SigningKey,
    ) -> String {
        let mut header = json!({ "alg": "EdDSA", "typ": "JWT" });
        if let Some(kid) = kid {
            header["kid"] = json!(kid);
        }
        let signing_input = format!(
            "{}.{}",
            b64u(header.to_string().as_bytes()),
            b64u(
                json!({ "iss": DID, "sub": "agent" })
                    .to_string()
                    .as_bytes()
            )
        );
        let signature = key.sign(signing_input.as_bytes());
        format!("{}.{}", signing_input, b64u(&signature.to_bytes()))
    }

    fn verify_against(
        methods: &[serde_json::Value],
        jwt: &str,
    ) -> Result<(), String> {
        let parsed = ParsedJwt::parse(jwt)?;
        let doc = json!({ "id": DID, "verificationMethod": methods });
        let verifier = match verification_key_from_did_document(&doc, parsed.kid())? {
            DidVerificationKey::Ed25519(key) => SignatureVerifier::EdDSA(key),
            DidVerificationKey::P256(key) => SignatureVerifier::ES256(key),
        };
        verifier.verify(
            parsed
                .signing_input()
                .as_bytes(),
            &parsed.signature_b64,
        )
    }

    #[test]
    fn mismatched_kid_on_multi_key_document_is_rejected() {
        let methods = two_key_document();
        let jwt = signed_jwt(Some(&format!("{}#key-9", DID)), &key(2));
        let err = verify_against(&methods, &jwt).expect_err("unknown kid must not fall back to another key");
        assert!(err.contains("key-9"), "{err}");
    }

    #[test]
    fn kid_naming_another_did_is_rejected() {
        let methods = two_key_document();
        let jwt = signed_jwt(Some("did:web:other.example.com#key-1"), &key(1));
        let err = verify_against(&methods, &jwt).expect_err("kid under another DID must be rejected");
        assert!(err.contains("does not belong"), "{err}");
    }

    #[test]
    fn missing_kid_on_multi_key_document_is_rejected() {
        let methods = two_key_document();
        let jwt = signed_jwt(None, &key(1));
        let err = verify_against(&methods, &jwt).expect_err("no kid against several keys is ambiguous");
        assert!(err.contains("no kid"), "{err}");
    }

    #[test]
    fn matching_kid_verifies_with_that_key_only() {
        let methods = two_key_document();
        verify_against(&methods, &signed_jwt(Some(&format!("{}#key-2", DID)), &key(2)))
            .expect("matching absolute kid must verify");

        let err = verify_against(&methods, &signed_jwt(Some(&format!("{}#key-1", DID)), &key(2)))
            .expect_err("kid selects key-1, which did not sign");
        assert!(err.contains("signature verification failed"), "{err}");
    }

    #[test]
    fn fragment_only_and_bare_kid_select_by_fragment() {
        let methods = two_key_document();
        verify_against(&methods, &signed_jwt(Some("#key-2"), &key(2))).expect("fragment-only kid must verify");
        verify_against(&methods, &signed_jwt(Some("key-2"), &key(2)))
            .expect("bare kid as emitted by VCIssuer::sign_jwt_with_typ must verify");
    }

    #[test]
    fn missing_kid_on_single_key_document_uses_that_key() {
        let methods = vec![jwk_method("key-1", &key(1))];
        verify_against(&methods, &signed_jwt(None, &key(1))).expect("single key is unambiguous");
        verify_against(&methods, &signed_jwt(None, &key(2))).expect_err("still a real signature check");
    }
}
