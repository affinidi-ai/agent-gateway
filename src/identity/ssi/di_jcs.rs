//! `eddsa-jcs-2022` Data-Integrity verification.
//!
//! `ssi` implements no JCS cryptosuite at any released version, and none exists
//! upstream either — so a credential signed by the Verifiable Trust Agent
//! (which signs `eddsa-jcs-2022`) cannot be verified through the `ssi` pipeline
//! the rest of this module uses. This supplies that one suite itself — the
//! procedure the VTA signs with, which `affinidi-data-integrity` cannot verify
//! for a proof bound to a challenge or a domain.
//!
//! **Scope is deliberately narrow.** This decides nothing: it answers "do these
//! bytes verify under this key" and nothing else. Proof presence, the
//! `verificationMethod`-belongs-to-the-controller binding, credential lifetime,
//! subject/holder agreement and revocation are all enforced once, on raw JSON,
//! in [`super::verifier`] — so they apply to every cryptosuite automatically
//! and cannot drift between the two verification paths.
//!
//! The reverse split is not possible: `affinidi-data-integrity` *does* support
//! `eddsa-rdfc-2022`, but its RDFC path expands JSON-LD against three hardcoded
//! bundled contexts and never fetches, so it cannot canonicalize a credential
//! carrying this gateway's own `AgentIdentityCredential` context. JCS needs no
//! context resolution at all, which is why only this direction works.

use affinidi_data_integrity::DataIntegrityError;
use affinidi_data_integrity::did_vm::{DidKeyResolver, ResolvedKey, VerificationMethodResolver};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::secrets::KeyType;
use anyhow::{Context as AnyhowContext, Result};
use async_trait::async_trait;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const JCS_CRYPTOSUITE: &str = "eddsa-jcs-2022";

/// Resolves a `verificationMethod` URI to its public key, for DID methods the
/// gateway already serves.
///
/// `did:key` is answered locally by the crate's own resolver (no I/O); anything
/// else goes through the shared DID cache, the same resolver the `ssi` path
/// uses — so both suites resolve identity from one source of truth rather than
/// two.
pub struct GatewayVmResolver {
    did_cache: Arc<DIDCacheClient>,
}

impl GatewayVmResolver {
    pub fn new(did_cache: Arc<DIDCacheClient>) -> Self {
        Self { did_cache }
    }
}

#[async_trait]
impl VerificationMethodResolver for GatewayVmResolver {
    async fn resolve_vm(
        &self,
        vm: &str,
    ) -> std::result::Result<ResolvedKey, DataIntegrityError> {
        if vm.starts_with("did:key:") {
            return DidKeyResolver
                .resolve_vm(vm)
                .await;
        }

        let did = vm
            .split('#')
            .next()
            .filter(|d| !d.is_empty())
            .ok_or_else(|| DataIntegrityError::Resolver(format!("verification method has no DID: {vm}")))?;

        let resolved = self
            .did_cache
            .resolve(did)
            .await
            .map_err(|e| DataIntegrityError::Resolver(format!("resolve {did}: {e}")))?;

        let doc = serde_json::to_value(&resolved.doc)
            .map_err(|e| DataIntegrityError::Resolver(format!("serialize DID document for {did}: {e}")))?;

        let method = find_verification_method(&doc, vm).ok_or_else(|| {
            DataIntegrityError::Resolver(format!("DID document for {did} declares no verification method {vm}"))
        })?;

        public_key_from_method(&method, vm)
    }
}

/// Find the verification method `vm` in a DID document.
///
/// Matches on the full URI and on the bare fragment, because a document may
/// write its method ids either way (`did:x:y#key-1` or `#key-1`).
fn find_verification_method(
    doc: &Value,
    vm: &str,
) -> Option<Value> {
    let fragment = vm
        .split_once('#')
        .map(|(_, f)| f);

    let matches = |entry: &Value| -> bool {
        let Some(id) = entry
            .get("id")
            .and_then(|i| i.as_str())
        else {
            return false;
        };
        id == vm || fragment.is_some_and(|f| id.strip_prefix('#') == Some(f))
    };

    // Embedded methods can appear under `verificationMethod` or inline in any
    // relationship array, so all of them are searched.
    const SECTIONS: &[&str] =
        &["verificationMethod", "authentication", "assertionMethod", "capabilityInvocation", "capabilityDelegation"];

    for section in SECTIONS {
        let entries = doc
            .get(section)
            .and_then(|s| s.as_array());
        if let Some(found) = entries
            .into_iter()
            .flatten()
            .find(|entry| entry.is_object() && matches(entry))
        {
            return Some(found.clone());
        }
    }
    None
}

/// Extract Ed25519 public key bytes from a verification method.
///
/// Only Ed25519 is accepted: `eddsa-jcs-2022` is defined over Ed25519 alone, so
/// a key of any other type here means the proof and the key disagree, which is
/// a rejection rather than something to coerce.
fn public_key_from_method(
    method: &Value,
    vm: &str,
) -> std::result::Result<ResolvedKey, DataIntegrityError> {
    let bad = DataIntegrityError::Resolver;

    if let Some(multibase) = method
        .get("publicKeyMultibase")
        .and_then(|k| k.as_str())
    {
        let (_base, bytes) =
            multibase::decode(multibase).map_err(|e| bad(format!("{vm}: publicKeyMultibase is not multibase: {e}")))?;
        // Multicodec `ed25519-pub` is 0xed 0x01, followed by the 32 key bytes.
        let key = match bytes.as_slice() {
            [0xed, 0x01, rest @ ..] => rest,
            _ => return Err(bad(format!("{vm}: publicKeyMultibase is not an Ed25519 key"))),
        };
        if key.len() != 32 {
            return Err(bad(format!("{vm}: Ed25519 key is {} bytes, expected 32", key.len())));
        }
        return Ok(ResolvedKey::new(KeyType::Ed25519, key.to_vec()));
    }

    if let Some(jwk) = method.get("publicKeyJwk") {
        let kty = jwk
            .get("kty")
            .and_then(|v| v.as_str());
        let crv = jwk
            .get("crv")
            .and_then(|v| v.as_str());
        if kty != Some("OKP") || crv != Some("Ed25519") {
            return Err(bad(format!("{vm}: publicKeyJwk is {kty:?}/{crv:?}, expected OKP/Ed25519")));
        }
        let x = jwk
            .get("x")
            .and_then(|v| v.as_str())
            .ok_or_else(|| bad(format!("{vm}: publicKeyJwk has no `x`")))?;
        let key = base64_url_decode(x).map_err(|e| bad(format!("{vm}: publicKeyJwk `x`: {e}")))?;
        if key.len() != 32 {
            return Err(bad(format!("{vm}: Ed25519 key is {} bytes, expected 32", key.len())));
        }
        return Ok(ResolvedKey::new(KeyType::Ed25519, key));
    }

    Err(bad(format!("{vm}: verification method carries neither publicKeyMultibase nor publicKeyJwk")))
}

fn base64_url_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .context("invalid base64url")
}

/// Verify one `eddsa-jcs-2022` proof over `document`.
///
/// `document` must be the credential or presentation **with its `proof` member
/// already removed** — JCS canonicalization is presence-sensitive, so hashing a
/// document that still carried a proof reproduces nothing a signer produced.
///
/// The signed bytes are `SHA-256(JCS(proof options)) || SHA-256(JCS(document))`,
/// where the proof options are every member of the proof except `proofValue`.
/// That includes a `challenge` and a `domain` when the proof carries them, which
/// is the reason this is done here rather than by `affinidi-data-integrity`:
/// its proof type has no such members, so it drops them and then reconstructs
/// bytes nobody signed — a proof bound to a challenge could never verify.
///
/// Only `eddsa-jcs-2022` is accepted, so this cannot be reached with a proof it
/// was not chosen for. Key resolution is the same [`GatewayVmResolver`] as
/// before; what the key is *allowed* to sign for stays decided in
/// [`super::verifier`].
pub async fn verify_jcs_proof(
    document: &Value,
    proof: &Value,
    did_cache: Arc<DIDCacheClient>,
) -> Result<()> {
    let members = proof
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("proof is not a Data Integrity proof"))?;
    let text = |name: &str| {
        members
            .get(name)
            .and_then(Value::as_str)
    };
    if text("type") != Some("DataIntegrityProof") {
        anyhow::bail!("proof is not a Data Integrity proof");
    }
    if text("cryptosuite") != Some(JCS_CRYPTOSUITE) {
        anyhow::bail!("eddsa-jcs-2022 verification was given a {:?} proof", text("cryptosuite"));
    }
    let verification_method =
        text("verificationMethod").ok_or_else(|| anyhow::anyhow!("proof names no verification method"))?;
    let proof_value = text("proofValue").ok_or_else(|| anyhow::anyhow!("proof carries no proofValue"))?;

    let (_, signature) = multibase::decode(proof_value).context("proofValue is not multibase")?;
    let signature = Signature::from_slice(&signature)
        .map_err(|e| anyhow::anyhow!("proofValue is not an Ed25519 signature: {e}"))?;

    let mut options = members.clone();
    options.remove("proofValue");
    let canonical = |value: &Value| {
        serde_json_canonicalizer::to_string(value)
            .map_err(|e| anyhow::anyhow!("canonicalising for eddsa-jcs-2022: {e}"))
    };
    let mut hash_data = Vec::with_capacity(64);
    hash_data.extend_from_slice(&Sha256::digest(canonical(&Value::Object(options))?.as_bytes()));
    hash_data.extend_from_slice(&Sha256::digest(canonical(document)?.as_bytes()));

    let key = GatewayVmResolver::new(did_cache)
        .resolve_vm(verification_method)
        .await
        .map_err(|e| anyhow::anyhow!("eddsa-jcs-2022 proof verification failed: {e}"))?;
    if key.key_type != KeyType::Ed25519 {
        anyhow::bail!("eddsa-jcs-2022 proof verification failed: {verification_method} is not an Ed25519 key");
    }
    let key: [u8; 32] = key
        .public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("eddsa-jcs-2022 proof verification failed: the key is not 32 bytes"))?;
    VerifyingKey::from_bytes(&key)
        .and_then(|key| key.verify_strict(&hash_data, &signature))
        .map_err(|e| anyhow::anyhow!("eddsa-jcs-2022 proof verification failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_multibase_ed25519_key_is_extracted() {
        // did:key z6Mk… multibase encodes 0xed01 ++ 32 key bytes.
        let key_bytes = [7u8; 32];
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(&key_bytes);
        let multibase = multibase::encode(multibase::Base::Base58Btc, &multicodec);

        let method = json!({ "id": "did:web:x#k1", "publicKeyMultibase": multibase });
        let resolved = public_key_from_method(&method, "did:web:x#k1").expect("key extracted");
        assert_eq!(resolved.public_key_bytes, key_bytes.to_vec());
    }

    #[test]
    fn a_jwk_ed25519_key_is_extracted() {
        use base64::Engine;
        let key_bytes = [9u8; 32];
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_bytes);
        let method = json!({
            "id": "did:web:x#k1",
            "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": x },
        });
        let resolved = public_key_from_method(&method, "did:web:x#k1").expect("key extracted");
        assert_eq!(resolved.public_key_bytes, key_bytes.to_vec());
    }

    /// `eddsa-jcs-2022` is Ed25519-only, so a P-256 method is a rejection and
    /// never something to coerce into a key.
    #[test]
    fn a_non_ed25519_key_is_refused() {
        let method = json!({
            "id": "did:web:x#k1",
            "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "AA", "y": "BB" },
        });
        let err = public_key_from_method(&method, "did:web:x#k1")
            .err()
            .map(|e| e.to_string())
            .expect("a P-256 method must be refused");
        assert!(err.contains("expected OKP/Ed25519"), "got: {err}");
    }

    #[test]
    fn a_method_with_no_key_material_is_refused() {
        let method = json!({ "id": "did:web:x#k1", "type": "Multikey" });
        assert!(public_key_from_method(&method, "did:web:x#k1").is_err());
    }

    #[test]
    fn a_truncated_key_is_refused() {
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(&[1u8; 16]);
        let multibase = multibase::encode(multibase::Base::Base58Btc, &multicodec);
        let method = json!({ "id": "did:web:x#k1", "publicKeyMultibase": multibase });
        let err = public_key_from_method(&method, "did:web:x#k1")
            .err()
            .map(|e| e.to_string())
            .expect("a short key must be refused");
        assert!(err.contains("expected 32"), "got: {err}");
    }

    #[test]
    fn a_method_is_found_by_full_uri_and_by_fragment() {
        let doc = json!({
            "verificationMethod": [{ "id": "did:web:x#k1", "publicKeyMultibase": "z1" }],
            "assertionMethod": [{ "id": "#k2", "publicKeyMultibase": "z2" }],
        });
        assert!(find_verification_method(&doc, "did:web:x#k1").is_some());
        assert!(
            find_verification_method(&doc, "did:web:x#k2").is_some(),
            "a method written as a bare fragment must still be found"
        );
        assert!(find_verification_method(&doc, "did:web:x#missing").is_none());
    }

    /// Relationship arrays hold bare *references* as strings as well as
    /// embedded methods; a reference carries no key and must not be mistaken
    /// for one.
    #[test]
    fn a_string_reference_is_not_mistaken_for_a_method() {
        let doc = json!({ "authentication": ["did:web:x#k1"] });
        assert!(find_verification_method(&doc, "did:web:x#k1").is_none());
    }
}
