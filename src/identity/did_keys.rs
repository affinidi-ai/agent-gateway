use base64::Engine;
use ed25519_dalek::Verifier as _;

/// A public key taken from a DID document verification method, in any of the
/// key types the gateway can verify signatures with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidVerificationKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
}

impl DidVerificationKey {
    /// The JOSE `alg` this key verifies.
    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "EdDSA",
            Self::P256(_) => "ES256",
        }
    }

    /// Verify a raw signature over `message`. ES256 accepts the JOSE `r || s`
    /// form and DER.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        match self {
            Self::Ed25519(key) => {
                let signature = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|e| format!("Invalid EdDSA signature: {e}"))?;
                key.verify(message, &signature)
                    .map_err(|_| "EdDSA signature verification failed".to_string())
            }
            Self::P256(key) => {
                let signature = if signature.len() == 64 {
                    p256::ecdsa::Signature::from_slice(signature)
                } else {
                    p256::ecdsa::Signature::from_der(signature).or_else(|_| p256::ecdsa::Signature::try_from(signature))
                }
                .map_err(|e| format!("Invalid ES256 signature: {e}"))?;
                key.verify(message, &signature)
                    .map_err(|_| "ES256 signature verification failed".to_string())
            }
        }
    }
}

/// Select a verification method from a resolved DID document and return its
/// public key.
///
/// `kid` must identify a verification method on the document: it matches the
/// method `id` exactly or by its `#fragment`. A `kid` that matches nothing is
/// an error, never a fallback to another key — selecting a different key than
/// the token names is key-purpose confusion on a multi-key document. With no
/// `kid` the document must publish exactly one method.
/// Supports `publicKeyJwk` (OKP/Ed25519, EC/P-256) and `publicKeyMultibase`
/// (Ed25519 and P-256 multicodec prefixes, or a bare 32-byte Ed25519 key).
pub fn verification_key_from_did_document(
    doc: &serde_json::Value,
    kid: Option<&str>,
) -> Result<DidVerificationKey, String> {
    let verification_methods = doc
        .get("verificationMethod")
        .and_then(|vm| vm.as_array())
        .ok_or("No verificationMethod found in DID document")?;

    let method = match kid {
        Some(kid_value) => {
            // A kid may be a bare fragment (`key-1`) or fully qualified
            // (`did:web:x#key-1`). When it is qualified it must name *this*
            // document, otherwise a fragment that happens to collide with one
            // of our methods would select our key for another DID's token.
            let (kid_did, fragment) = kid_value
                .split_once('#')
                .unwrap_or(("", kid_value));
            if !kid_did.is_empty()
                && let Some(doc_did) = doc
                    .get("id")
                    .and_then(|id| id.as_str())
                && kid_did != doc_did
            {
                return Err(format!("kid '{kid_value}' does not belong to {doc_did}"));
            }
            verification_methods
                .iter()
                .find(|vm| {
                    vm.get("id")
                        .and_then(|id| id.as_str())
                        .is_some_and(|id| {
                            id == kid_value
                                || id
                                    .rsplit_once('#')
                                    .is_some_and(|(_, id_fragment)| id_fragment == fragment)
                        })
                })
                .ok_or_else(|| {
                    format!("kid '{kid_value}' does not identify a verification method on the DID document")
                })?
        }
        None => match verification_methods.as_slice() {
            [only] => only,
            _ => {
                return Err(format!(
                    "no kid given and the DID document publishes {} verification methods",
                    verification_methods.len()
                ));
            }
        },
    };

    if let Some(jwk) = method.get("publicKeyJwk") {
        return verification_key_from_jwk(jwk);
    }

    if let Some(multibase_key) = method
        .get("publicKeyMultibase")
        .and_then(|v| v.as_str())
    {
        return verification_key_from_multibase(multibase_key);
    }

    Err("No supported public key format found in verification method".to_string())
}

/// Build a verification key from a JWK. Private components, if present, are
/// ignored, so a stored private JWK works as well as a public one.
pub fn verification_key_from_jwk(jwk: &serde_json::Value) -> Result<DidVerificationKey, String> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .unwrap_or("OKP");
    let crv = jwk
        .get("crv")
        .and_then(|v| v.as_str())
        .unwrap_or("Ed25519");

    match (kty, crv) {
        ("OKP", "Ed25519") => {
            let x = decode_jwk_coordinate(jwk, "x")?;
            ed25519_from_bytes(&x, "JWK")
        }
        ("EC", "P-256") => {
            let x = decode_jwk_coordinate(jwk, "x")?;
            let y = decode_jwk_coordinate(jwk, "y")?;
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            p256_from_sec1(&sec1, "JWK")
        }
        (kty, crv) => Err(format!("Unsupported JWK key type {kty}/{crv}")),
    }
}

fn decode_jwk_coordinate(
    jwk: &serde_json::Value,
    name: &str,
) -> Result<Vec<u8>, String> {
    let value = jwk
        .get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("JWK missing '{name}' coordinate"))?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| format!("Failed to decode JWK '{name}': {e}"))
}

fn verification_key_from_multibase(multibase: &str) -> Result<DidVerificationKey, String> {
    let decoded = decode_multibase(multibase)?;
    match decoded.as_slice() {
        [0xed, 0x01, key @ ..] => ed25519_from_bytes(key, "multibase"),
        [0x80, 0x24, key @ ..] => p256_from_sec1(key, "multibase"),
        key if key.len() == 32 => ed25519_from_bytes(key, "multibase"),
        _ => Err("Unsupported multibase key encoding".to_string()),
    }
}

/// Decode a `z`-prefixed base58btc multibase value to its raw bytes,
/// including any multicodec prefix.
pub fn decode_multibase(multibase: &str) -> Result<Vec<u8>, String> {
    if !multibase.starts_with('z') {
        return Err(format!(
            "Unsupported multibase prefix: {}",
            multibase
                .chars()
                .next()
                .unwrap_or('?')
        ));
    }
    bs58::decode(&multibase[1..])
        .into_vec()
        .map_err(|e| format!("Base58 decode error: {}", e))
}

fn ed25519_from_bytes(
    bytes: &[u8],
    source: &str,
) -> Result<DidVerificationKey, String> {
    let public_key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("Invalid Ed25519 public key length from {source}"))?;
    ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)
        .map(DidVerificationKey::Ed25519)
        .map_err(|e| format!("Invalid Ed25519 public key from {source}: {e}"))
}

fn p256_from_sec1(
    bytes: &[u8],
    source: &str,
) -> Result<DidVerificationKey, String> {
    p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
        .map(DidVerificationKey::P256)
        .map_err(|e| format!("Invalid P-256 public key from {source}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssi::jwk::JWK;

    fn document_with_methods(
        did: &str,
        keys: &[(&str, &JWK)],
    ) -> serde_json::Value {
        let methods: Vec<serde_json::Value> = keys
            .iter()
            .map(|(fragment, key)| {
                serde_json::json!({
                    "id": format!("{did}#{fragment}"),
                    "type": "JsonWebKey2020",
                    "controller": did,
                    "publicKeyJwk": serde_json::to_value(key.to_public()).unwrap(),
                })
            })
            .collect();
        serde_json::json!({ "id": did, "verificationMethod": methods })
    }

    fn public_jwk(key: &JWK) -> serde_json::Value {
        serde_json::to_value(key.to_public()).unwrap()
    }

    #[test]
    fn key_lookup_from_document_needs_no_api_state() {
        let key = JWK::generate_ed25519().unwrap();
        let doc = document_with_methods("did:web:example.com", &[("key-1", &key)]);

        let found = verification_key_from_did_document(&doc, None).unwrap();

        assert_eq!(found, verification_key_from_jwk(&public_jwk(&key)).unwrap());
        assert_eq!(found.algorithm(), "EdDSA");
    }

    #[test]
    fn selects_method_by_full_id() {
        let first = JWK::generate_ed25519().unwrap();
        let second = JWK::generate_ed25519().unwrap();
        let doc = document_with_methods("did:web:example.com", &[("key-1", &first), ("key-2", &second)]);

        let found = verification_key_from_did_document(&doc, Some("did:web:example.com#key-2")).unwrap();

        assert_eq!(found, verification_key_from_jwk(&public_jwk(&second)).unwrap());
    }

    #[test]
    fn selects_method_by_fragment() {
        let first = JWK::generate_ed25519().unwrap();
        let second = JWK::generate_ed25519().unwrap();
        let doc = document_with_methods("did:web:example.com", &[("key-1", &first), ("key-2", &second)]);

        let found = verification_key_from_did_document(&doc, Some("key-2")).unwrap();

        assert_eq!(found, verification_key_from_jwk(&public_jwk(&second)).unwrap());
    }

    #[test]
    fn rejects_a_kid_that_matches_no_method() {
        let first = JWK::generate_ed25519().unwrap();
        let second = JWK::generate_ed25519().unwrap();
        let doc = document_with_methods("did:web:example.com", &[("key-1", &first), ("key-2", &second)]);

        // Falling back to the first method here would verify the token under a
        // key it never named: key-purpose confusion on a multi-key document.
        let err = verification_key_from_did_document(&doc, Some("missing")).unwrap_err();

        assert!(err.contains("does not identify a verification method"), "{err}");
    }

    #[test]
    fn rejects_a_missing_kid_on_a_multi_key_document() {
        let first = JWK::generate_ed25519().unwrap();
        let second = JWK::generate_ed25519().unwrap();
        let doc = document_with_methods("did:web:example.com", &[("key-1", &first), ("key-2", &second)]);

        let err = verification_key_from_did_document(&doc, None).unwrap_err();

        assert!(err.contains("publishes 2 verification methods"), "{err}");
    }

    #[test]
    fn decodes_p256_jwk() {
        let key = JWK::generate_p256();
        let doc = document_with_methods("did:web:example.com", &[("key-p256-1", &key)]);

        let found = verification_key_from_did_document(&doc, Some("key-p256-1")).unwrap();

        assert_eq!(found.algorithm(), "ES256");
        assert!(matches!(found, DidVerificationKey::P256(_)));
    }

    #[test]
    fn p256_key_verifies_es256_signature() {
        use p256::ecdsa::signature::Signer as _;
        let jwk = serde_json::to_value(JWK::generate_p256()).unwrap();
        let d = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwk["d"].as_str().unwrap())
            .unwrap();
        let signing_key = p256::ecdsa::SigningKey::from_slice(&d).unwrap();
        let verifying = verification_key_from_jwk(&jwk).unwrap();
        assert_eq!(verifying, DidVerificationKey::P256(*signing_key.verifying_key()));
        let signature: p256::ecdsa::Signature = signing_key.sign(b"payload");

        assert_eq!(verifying.verify(b"payload", &signature.to_bytes()), Ok(()));
        assert_eq!(verifying.verify(b"payload", signature.to_der().as_bytes()), Ok(()));
        assert!(
            verifying
                .verify(b"other", &signature.to_bytes())
                .is_err()
        );
    }

    #[test]
    fn private_jwk_is_accepted_as_a_public_key_source() {
        let key = JWK::generate_ed25519().unwrap();
        let private = serde_json::to_value(&key).unwrap();
        assert!(private.get("d").is_some(), "fixture must be a private JWK");

        let from_private = verification_key_from_jwk(&private).unwrap();

        assert_eq!(from_private, verification_key_from_jwk(&public_jwk(&key)).unwrap());
    }

    #[test]
    fn unsupported_jwk_type_is_rejected() {
        let err = verification_key_from_jwk(&serde_json::json!({ "kty": "RSA", "crv": "none" })).unwrap_err();

        assert_eq!(err, "Unsupported JWK key type RSA/none");
    }

    #[test]
    fn document_without_verification_methods_is_an_error() {
        let doc = serde_json::json!({ "id": "did:web:example.com" });

        let err = verification_key_from_did_document(&doc, None).unwrap_err();

        assert_eq!(err, "No verificationMethod found in DID document");
    }

    #[test]
    fn multibase_ed25519_with_multicodec_prefix_decodes() {
        let key = JWK::generate_ed25519().unwrap();
        let x = public_jwk(&key)["x"]
            .as_str()
            .unwrap()
            .to_string();
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(x)
            .unwrap();
        let mut prefixed = vec![0xed, 0x01];
        prefixed.extend_from_slice(&raw);
        let doc = serde_json::json!({
            "id": "did:key:z",
            "verificationMethod": [{
                "id": "did:key:z#key-2",
                "type": "Multikey",
                "publicKeyMultibase": format!("z{}", bs58::encode(prefixed).into_string()),
            }]
        });

        let found = verification_key_from_did_document(&doc, None).unwrap();

        assert_eq!(found, verification_key_from_jwk(&public_jwk(&key)).unwrap());
    }

    #[test]
    fn multibase_without_z_prefix_is_rejected() {
        let err = decode_multibase("mABC").unwrap_err();

        assert_eq!(err, "Unsupported multibase prefix: m");
    }
}
