//! `eddsa-jcs-2022` Data-Integrity proof over a Trust Task document.
//!
//! The VTA authenticates a holder-submitted Trust Task by verifying this proof
//! with a `did:key` resolver (the proof's `verificationMethod` is the proven
//! signer). The recipe is reproduced **exactly** from the VTA's signer
//! (`affinidi-data-integrity` `eddsa-jcs-2022`) so the proof the gateway
//! produces verifies there byte-for-byte:
//!
//! 1. `transformedDocument = JCS(document without its `proof`)`.
//! 2. `proofConfig = { type, cryptosuite, created, verificationMethod,
//!    proofPurpose }` (no `proofValue`, no `@context` for auth).
//! 3. `canonicalProofConfig = JCS(proofConfig)`.
//! 4. `hashData = SHA256(canonicalProofConfig) || SHA256(transformedDocument)`
//!    — **proof hash first**, then document hash.
//! 5. `signature = Ed25519(hashData)`.
//! 6. `proofValue = multibase-base58btc(signature)` (a `z…` string).
//!
//! JCS is RFC 8785 (`serde_json_canonicalizer`), which sorts object keys, so
//! field order here is irrelevant — only the set of members matters.
//!
//! It is deliberately **not** `serde_jcs`: this binary builds `serde_json` with
//! `arbitrary_precision` (the alloy stack enables it), and under that feature
//! `serde_jcs` serialises every number through an unimplemented path and
//! panics. Signed documents routinely carry numbers — a JWT's `exp` and `iat`
//! among them — so that would abort the process on the signing path.

use chrono::{SecondsFormat, Utc};
use multibase::Base;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::control_key::SignerKeyProvider;
use super::error::VtaError;

pub const CRYPTOSUITE_EDDSA_JCS_2022: &str = "eddsa-jcs-2022";
pub const PROOF_TYPE_DATA_INTEGRITY: &str = "DataIntegrityProof";
/// The signer proves control of the identifier (not a third-party attestation).
pub const PROOF_PURPOSE_AUTHENTICATION: &str = "authentication";

fn jcs(value: &Value) -> Result<String, VtaError> {
    serde_json_canonicalizer::to_string(value).map_err(|e| VtaError::Signing(format!("JCS canonicalisation: {e}")))
}

/// Produce the `eddsa-jcs-2022` proof object for `document` (which must **not**
/// already carry a `proof` member) signed by `key` for `proof_purpose`.
pub async fn sign_document(
    document: &Value,
    key: &dyn SignerKeyProvider,
    proof_purpose: &str,
) -> Result<Value, VtaError> {
    let created = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);

    // Proof config is the proof object **without** proofValue.
    let proof_config = json!({
        "type": PROOF_TYPE_DATA_INTEGRITY,
        "cryptosuite": CRYPTOSUITE_EDDSA_JCS_2022,
        "created": created,
        "verificationMethod": key.verification_method(),
        "proofPurpose": proof_purpose,
    });

    let transformed_document = jcs(document)?;
    let canonical_proof_config = jcs(&proof_config)?;

    let mut hash_data = Vec::with_capacity(64);
    hash_data.extend_from_slice(&Sha256::digest(canonical_proof_config.as_bytes()));
    hash_data.extend_from_slice(&Sha256::digest(transformed_document.as_bytes()));

    let signature = key.sign(&hash_data).await?;
    let proof_value = multibase::encode(Base::Base58Btc, signature);

    let mut proof = proof_config;
    proof
        .as_object_mut()
        .expect("proof_config is an object")
        .insert("proofValue".to_string(), Value::String(proof_value));
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vta::control_key::ControlKey;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn verifying_key(key: &ControlKey) -> VerifyingKey {
        let mb = key
            .did()
            .strip_prefix("did:key:")
            .unwrap();
        let (_b, prefixed) = multibase::decode(mb).unwrap();
        let pk: [u8; 32] = prefixed[2..]
            .try_into()
            .unwrap();
        VerifyingKey::from_bytes(&pk).unwrap()
    }

    /// Recompute the hash the way the VTA will and confirm the emitted
    /// `proofValue` verifies — i.e. the gateway reproduces the VTA's recipe.
    #[tokio::test]
    async fn proof_value_verifies_under_the_vta_recipe() {
        let key = ControlKey::from_seed([3u8; 32]);
        let doc = json!({
            "id": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "type": "https://trusttasks.org/spec/auth/authenticate/0.2",
            "issuer": key.did(),
            "recipient": "did:webvh:vta.example",
            "payload": { "challenge": "abc", "sessionId": "s1", "scope": [] }
        });

        let proof = sign_document(&doc, &key, PROOF_PURPOSE_AUTHENTICATION)
            .await
            .unwrap();

        assert_eq!(proof["type"], json!(PROOF_TYPE_DATA_INTEGRITY));
        assert_eq!(proof["cryptosuite"], json!(CRYPTOSUITE_EDDSA_JCS_2022));
        assert_eq!(proof["proofPurpose"], json!(PROOF_PURPOSE_AUTHENTICATION));
        let proof_value = proof["proofValue"]
            .as_str()
            .expect("proofValue string");
        assert!(proof_value.starts_with('z'), "multibase base58btc: {proof_value}");

        // Reconstruct hashData exactly as the verifier does: proof config is the
        // proof minus proofValue; hash is SHA256(proofConfig) || SHA256(doc).
        let mut config = proof.clone();
        config
            .as_object_mut()
            .unwrap()
            .remove("proofValue");
        let canonical_proof_config = jcs(&config).unwrap();
        let transformed_document = jcs(&doc).unwrap();
        let mut hash_data = Vec::new();
        hash_data.extend_from_slice(&Sha256::digest(canonical_proof_config.as_bytes()));
        hash_data.extend_from_slice(&Sha256::digest(transformed_document.as_bytes()));

        let (_b, sig_bytes) = multibase::decode(proof_value).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        verifying_key(&key)
            .verify(&hash_data, &sig)
            .expect("proofValue verifies over SHA256(proofConfig)||SHA256(doc)");
    }

    #[tokio::test]
    async fn signing_is_presence_sensitive_to_proof_member() {
        // The document must be signed proof-less; a stray `proof` key changes
        // the canonical bytes. Guard that we never sign a doc carrying one.
        let key = ControlKey::from_seed([9u8; 32]);
        let clean = json!({ "id": "x", "payload": {} });
        let with_proof = json!({ "id": "x", "payload": {}, "proof": { "stale": true } });
        let a = sign_document(&clean, &key, PROOF_PURPOSE_AUTHENTICATION)
            .await
            .unwrap();
        let b = sign_document(&with_proof, &key, PROOF_PURPOSE_AUTHENTICATION)
            .await
            .unwrap();
        assert_ne!(a["proofValue"], b["proofValue"], "proof presence changes the signature");
    }

    /// Numbers must canonicalise rather than abort the process.
    ///
    /// This binary builds `serde_json` with `arbitrary_precision`, under which
    /// `serde_jcs` routes every number through an unimplemented path and
    /// panics. Every signed token carries numeric `exp`/`iat`, so that would
    /// take the signing path down on ordinary input — and a document whose
    /// numbers come from a caller would make it reachable from outside.
    #[tokio::test]
    async fn a_document_carrying_numbers_signs_rather_than_panicking() {
        let key = ControlKey::from_seed([5u8; 32]);
        let doc = json!({
            "id": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "payload": {
                "keyId": "gateway-jwt",
                "payload": { "sub": "urn:agent:demo", "iat": 1_761_000_000, "exp": 1_761_000_900, "amount": 1.5 },
            },
        });

        let proof = sign_document(&doc, &key, PROOF_PURPOSE_AUTHENTICATION)
            .await
            .expect("a document with numeric claims must sign");
        assert!(
            proof["proofValue"]
                .as_str()
                .is_some_and(|v| v.starts_with('z')),
            "a numeric claim set still yields a multibase proof value"
        );
    }

    /// RFC 8785 orders object members by key, so the same claims in a different
    /// source order must produce the same signing input — the property the VTA
    /// relies on when it re-canonicalises what it received.
    #[test]
    fn member_order_does_not_change_the_canonical_form() {
        let a = json!({ "id": "x", "payload": { "exp": 2, "iat": 1 } });
        let b = json!({ "payload": { "iat": 1, "exp": 2 }, "id": "x" });
        assert_eq!(jcs(&a).unwrap(), jcs(&b).unwrap(), "JCS sorts members");
    }
}
