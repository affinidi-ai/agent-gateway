//! The gateway's own signing keys, signed by the VTA's signing library.
//!
//! Local signing keeps the gateway's keys and DIDs exactly as they are on disk:
//! the key files stay the source of truth, and nothing new is persisted. What
//! makes the signature is `vta-signing`, the code the VTA's own signing
//! operations use, so a signing fix reaches the gateway and the VTA together.
//! The gateway adds none of the VTA's key custody, access control or audit: it
//! signs with keys it already holds in memory.

mod signers;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde_json::{Map, Value};
use vta_signing::SigningSecret;
use vta_signing::jws::{JwsPayload, refuse_x5c, sign_jws};
use zeroize::Zeroizing;

use super::error::VtaError;

pub use signers::{VtaDiSigner, VtaSsiSigner};

/// The Ed25519 key of a JWK's private part (`d`).
pub fn secret_of(key: &ssi::jwk::JWK) -> Result<SigningSecret, VtaError> {
    let json = serde_json::to_value(key).map_err(signing_error)?;
    let d = json
        .get("d")
        .and_then(Value::as_str)
        .ok_or_else(|| VtaError::Signing("local signing: the key has no private part".to_string()))?;
    let bytes = Zeroizing::new(
        B64URL
            .decode(d)
            .map_err(|e| VtaError::Signing(format!("local signing: the private key is not base64url: {e}")))?,
    );
    SigningSecret::ed25519_from_slice(&bytes).map_err(|e| VtaError::Signing(format!("local signing: {e}")))
}

fn signing_error(detail: impl std::fmt::Display) -> VtaError {
    VtaError::Signing(format!("local signing: {detail}"))
}

/// A compact JWS of `payload` under the header `{typ, kid}` (plus the `alg` the
/// key names), signed by the Ed25519 key of `key`. The payload is signed as the
/// gateway serialises it, byte for byte.
pub fn sign_jwt(
    key: &ssi::jwk::JWK,
    typ: &str,
    payload: &Value,
) -> Result<String, VtaError> {
    let secret = secret_of(key)?;
    let mut header = Map::new();
    header.insert("typ".to_string(), Value::String(typ.to_string()));
    header.insert(
        "kid".to_string(),
        Value::String(
            key.key_id
                .clone()
                .unwrap_or_else(|| "key-1".to_string()),
        ),
    );
    let payload_b64 = B64URL.encode(serde_json::to_string(payload).map_err(signing_error)?);
    sign_jws(&secret, &header, JwsPayload::Base64Url(&payload_b64), refuse_x5c).map_err(signing_error)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::json;
    use ssi::jwk::JWK;

    use super::*;

    fn jwk() -> JWK {
        JWK::generate_ed25519().expect("key")
    }

    fn public_of(key: &JWK) -> vta_signing::PublicKey {
        use vta_signing::Signer as _;
        secret_of(key)
            .expect("secret")
            .public_key()
    }

    #[test]
    fn a_token_verifies_under_the_gateways_published_key_and_carries_what_the_gateway_signed() {
        let key = jwk();
        let payload = json!({ "sub": "agent", "n": { "b": 1, "a": "x" }, "iat": 1_700_000_000 });

        let jwt = sign_jwt(&key, "at+jwt", &payload).expect("signed");

        let verified = vta_signing::jws::verify_jws(&jwt, &public_of(&key)).expect("verifies");
        assert_eq!(verified.header["typ"], "at+jwt");
        assert_eq!(verified.header["kid"], "key-1", "the kid defaults to key-1");
        assert_eq!(verified.header["alg"], "EdDSA");
        assert_eq!(
            verified.payload,
            serde_json::to_string(&payload)
                .unwrap()
                .into_bytes(),
            "the payload is signed byte for byte as the gateway serialises it"
        );
    }

    #[test]
    fn the_jwks_key_id_is_the_kid() {
        let mut key = jwk();
        key.key_id = Some("gw-1".to_string());

        let jwt = sign_jwt(&key, "JWT", &json!({})).expect("signed");

        let verified = vta_signing::jws::verify_jws(&jwt, &public_of(&key)).expect("verifies");
        assert_eq!(verified.header["kid"], "gw-1");
    }

    /// Ed25519 is deterministic, so the signature is the same bytes the gateway's
    /// own signing code made before the library took over.
    #[test]
    fn the_signature_is_what_the_key_signs_over_the_same_signing_input() {
        let key = jwk();
        let jwt = sign_jwt(&key, "JWT", &json!({ "a": 1 })).expect("signed");

        let parts: Vec<&str> = jwt.split('.').collect();
        let d = serde_json::to_value(&key).unwrap()["d"]
            .as_str()
            .unwrap()
            .to_string();
        let seed: [u8; 32] = B64URL
            .decode(d)
            .unwrap()
            .try_into()
            .unwrap();
        let reference = SigningKey::from_bytes(&seed).sign(format!("{}.{}", parts[0], parts[1]).as_bytes());

        assert_eq!(
            B64URL
                .decode(parts[2])
                .unwrap(),
            reference.to_bytes().to_vec()
        );
    }

    #[test]
    fn a_key_without_a_private_part_signs_nothing() {
        let public = jwk().to_public();

        assert!(matches!(sign_jwt(&public, "JWT", &json!({})), Err(VtaError::Signing(_))));
    }
}
