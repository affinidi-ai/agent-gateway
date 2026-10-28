//! The gateway's **control key** — the Ed25519 `did:key` the gateway
//! authenticates to the VTA with (VTA-02/03).
//!
//! This is **not** an issuer/signing key: it only proves control of the
//! gateway's auth identity when it signs the `auth/authenticate/0.2` Trust Task.
//!
//! Signing goes through the [`SignerKeyProvider`] seam so the key material can
//! be swapped for a **non-exportable KMS/HSM** key without touching the auth
//! handshake: [`ControlKey`] is the in-memory implementation; a KMS-backed
//! provider would implement the same trait and sign remotely, never exposing
//! the private key to the gateway process.

use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use multibase::Base;

use super::error::VtaError;

/// Multicodec prefix for an Ed25519 public key (`0xed`, varint `0x01`).
const ED25519_PUB_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Signing seam for the gateway's auth/control key.
///
/// Implementors expose the public identity (`did:key` + verification method) and
/// sign a message — but **never** expose the private key. [`ControlKey`] holds
/// the key in memory; a future KMS/HSM provider signs out-of-process behind the
/// same interface (rung 3: non-exportable), so no call site changes when the key
/// custody hardens.
#[async_trait]
pub trait SignerKeyProvider: Send + Sync {
    /// The control `did:key`.
    fn did(&self) -> &str;

    /// The verification method the auth proof names (`did:key:z…#z…`).
    fn verification_method(&self) -> &str;

    /// Raw Ed25519 signature over `message` (pure EdDSA; the VTA verifies with
    /// `verify_strict` over the same bytes). Async because a KMS/HSM signer
    /// performs I/O.
    async fn sign(
        &self,
        message: &[u8],
    ) -> Result<[u8; 64], VtaError>;
}

/// An Ed25519 control key and its `did:key` identity.
pub struct ControlKey {
    signing: SigningKey,
    did: String,
    verification_method: String,
}

// Hand-written so the secret never reaches a log via a derived `Debug`.
impl std::fmt::Debug for ControlKey {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("ControlKey")
            .field("did", &self.did)
            .field("signing", &"<redacted>")
            .finish()
    }
}

impl ControlKey {
    /// Build from a 32-byte Ed25519 seed (the private scalar seed).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let public = signing
            .verifying_key()
            .to_bytes();
        let mut prefixed = Vec::with_capacity(2 + public.len());
        prefixed.extend_from_slice(&ED25519_PUB_MULTICODEC);
        prefixed.extend_from_slice(&public);
        let mb = multibase::encode(Base::Base58Btc, &prefixed);
        let did = format!("did:key:{mb}");
        // A did:key names its verification method as `<did>#<multibase-key>`.
        let verification_method = format!("{did}#{mb}");
        Self {
            signing,
            did,
            verification_method,
        }
    }

    /// Generate a fresh random control key (CSPRNG seed).
    pub fn generate() -> Self {
        // `rand` (rand_core 0.9) and `ed25519-dalek` (rand_core 0.6) disagree on
        // the `RngCore` version, so seed via raw random bytes rather than
        // `SigningKey::generate`.
        let seed: [u8; 32] = rand::random();
        Self::from_seed(seed)
    }

    /// The 32-byte Ed25519 seed (the private scalar seed). Handle as a secret.
    ///
    /// Exposed so the gateway can publish a `did:webvh` whose verification
    /// method is this key — the document needs the public half, and the birth
    /// entry has to be signed by the private one.
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// The 32-byte seed, hex-encoded — for persisting the key at rest (through
    /// the encrypted secret-file helper). Handle as a secret.
    pub fn seed_hex(&self) -> String {
        let seed = self.seed_bytes();
        let mut out = String::with_capacity(64);
        for byte in seed {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    /// Re-point this key at a **stable** identifier whose lifetime is
    /// independent of the key — a `did:webvh` (VTA-13).
    ///
    /// With a `did:key` the identifier *is* the key, so rotating the key means
    /// a new identity and a fresh VTA grant. A `did:webvh` keeps the
    /// identifier while the key rotates at the DID document, so the ACL grant,
    /// the audit trail and the relationship all survive a rotation.
    ///
    /// The signing key is unchanged — only what the auth proof *calls itself*
    /// changes. The update key that can re-point verification methods stays
    /// off this host; nothing here can rewrite the DID document.
    ///
    /// `verification_method` must be a method id declared by that DID document
    /// for this key. Absent, `<did>#key-1` is assumed, which is what the VTA's
    /// own `did:webvh` provisioning emits.
    pub fn with_stable_did(
        mut self,
        did: String,
        verification_method: Option<String>,
    ) -> Result<Self, VtaError> {
        if !did.starts_with("did:webvh:") {
            return Err(VtaError::Config(format!(
                "[vta] auth_did must be a did:webvh (a stable identifier whose key can rotate); got `{did}`"
            )));
        }
        let vm = match verification_method {
            Some(vm) if vm.starts_with('#') => format!("{did}{vm}"),
            Some(vm) if vm.starts_with("did:") => {
                if !vm.starts_with(&format!("{did}#")) {
                    return Err(VtaError::Config(format!(
                        "[vta] auth_verification_method `{vm}` does not belong to auth_did `{did}`"
                    )));
                }
                vm
            }
            Some(vm) => format!("{did}#{vm}"),
            None => format!("{did}#key-1"),
        };
        self.did = did;
        self.verification_method = vm;
        Ok(self)
    }

    /// The multibase public key this control key signs with, as a DID document
    /// records it (`z…`, `0xed01 ++ pubkey`).
    ///
    /// Lets a caller check that the DID document a stable identifier resolves
    /// to actually declares *this* key, which is the difference between a
    /// rotation that was published and one that was only intended.
    pub fn public_key_multibase(&self) -> String {
        let public = self
            .signing
            .verifying_key()
            .to_bytes();
        let mut prefixed = Vec::with_capacity(2 + public.len());
        prefixed.extend_from_slice(&ED25519_PUB_MULTICODEC);
        prefixed.extend_from_slice(&public);
        multibase::encode(Base::Base58Btc, &prefixed)
    }
}

#[async_trait]
impl SignerKeyProvider for ControlKey {
    fn did(&self) -> &str {
        &self.did
    }

    fn verification_method(&self) -> &str {
        &self.verification_method
    }

    async fn sign(
        &self,
        message: &[u8],
    ) -> Result<[u8; 64], VtaError> {
        Ok(self
            .signing
            .sign(message)
            .to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    /// A fixed seed gives a stable, inspectable did:key.
    fn fixed_key() -> ControlKey {
        ControlKey::from_seed([7u8; 32])
    }

    #[test]
    fn did_key_is_well_formed_ed25519_multibase() {
        let key = fixed_key();
        let did = key.did();
        assert!(did.starts_with("did:key:z"), "ed25519 did:key is base58btc multibase: {did}");
        // The verification method is `<did>#<same-multibase>`.
        let (d, frag) = key
            .verification_method()
            .split_once('#')
            .expect("vm has a fragment");
        assert_eq!(d, did);
        assert_eq!(format!("did:key:{frag}"), did, "fragment repeats the multibase key");
    }

    #[test]
    fn decoded_did_key_carries_the_ed25519_multicodec_prefix_and_public_key() {
        let key = fixed_key();
        let mb = key
            .did()
            .strip_prefix("did:key:")
            .unwrap();
        let (_base, bytes) = multibase::decode(mb).expect("valid multibase");
        assert_eq!(&bytes[..2], &ED25519_PUB_MULTICODEC, "0xed01 ed25519-pub prefix");
        assert_eq!(bytes.len(), 2 + 32, "prefix + 32-byte public key");
    }

    #[tokio::test]
    async fn signature_verifies_against_the_derived_public_key() {
        let key = fixed_key();
        let mb = key
            .did()
            .strip_prefix("did:key:")
            .unwrap();
        let (_b, prefixed) = multibase::decode(mb).unwrap();
        let pk_bytes: [u8; 32] = prefixed[2..]
            .try_into()
            .unwrap();
        let vk = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let msg = b"hash-data-under-test";
        let sig = Signature::from_bytes(&key.sign(msg).await.unwrap());
        vk.verify(msg, &sig)
            .expect("signature verifies under the did:key public key");
    }

    #[test]
    fn generated_keys_are_distinct() {
        assert_ne!(ControlKey::generate().did(), ControlKey::generate().did());
    }

    #[test]
    fn seed_hex_round_trips_to_the_same_identity() {
        let key = ControlKey::from_seed([11u8; 32]);
        let hex = key.seed_hex();
        assert_eq!(hex.len(), 64);
        // Re-deriving from the persisted seed yields the same did:key.
        let bytes: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let restored = ControlKey::from_seed(bytes.try_into().unwrap());
        assert_eq!(restored.did(), key.did());
    }

    // ─── Stable `did:webvh` identifier (VTA-13) ──────────────────────────

    const WEBVH: &str = "did:webvh:QmExample:gateway.example";

    /// The property the whole ticket exists for: rotating the signing key
    /// leaves the identifier unchanged, so the VTA's ACL grant, its audit trail
    /// and the relationship survive a rotation. With a `did:key` the same
    /// rotation produces a different identity and needs a fresh grant.
    #[test]
    fn rotating_the_key_under_a_stable_did_keeps_the_identifier() {
        let before = ControlKey::from_seed([1u8; 32])
            .with_stable_did(WEBVH.to_string(), None)
            .expect("a did:webvh identifier is accepted");
        let after = ControlKey::from_seed([2u8; 32])
            .with_stable_did(WEBVH.to_string(), None)
            .expect("a did:webvh identifier is accepted");

        assert_eq!(before.did(), after.did(), "the identifier must survive rotation");
        assert_eq!(
            before.verification_method(),
            after.verification_method(),
            "a rotation that keeps the method id needs no config change"
        );
        assert_ne!(before.public_key_multibase(), after.public_key_multibase(), "the key really did rotate");

        // The contrast: with did:key the identifier *is* the key.
        assert_ne!(
            ControlKey::from_seed([1u8; 32]).did(),
            ControlKey::from_seed([2u8; 32]).did(),
            "a did:key identity cannot survive rotation, which is why this exists"
        );
    }

    /// `did:key` is rejected for a stable identifier: accepting one would look
    /// like it worked and then fail to survive the first rotation.
    #[test]
    fn a_did_key_is_refused_as_a_stable_identifier() {
        let err = ControlKey::from_seed([3u8; 32])
            .with_stable_did("did:key:z6MkSomething".to_string(), None)
            .err()
            .map(|e| format!("{e:?}"))
            .expect("did:key must be refused");
        assert!(err.contains("did:webvh"), "the refusal should name what is wanted: {err}");
    }

    #[test]
    fn a_verification_method_may_be_given_as_a_fragment_or_in_full() {
        let bare = ControlKey::from_seed([4u8; 32])
            .with_stable_did(WEBVH.to_string(), Some("key-2".to_string()))
            .expect("bare fragment");
        let hashed = ControlKey::from_seed([4u8; 32])
            .with_stable_did(WEBVH.to_string(), Some("#key-2".to_string()))
            .expect("#fragment");
        let full = ControlKey::from_seed([4u8; 32])
            .with_stable_did(WEBVH.to_string(), Some(format!("{WEBVH}#key-2")))
            .expect("full URI");

        let expected = format!("{WEBVH}#key-2");
        assert_eq!(bare.verification_method(), expected);
        assert_eq!(hashed.verification_method(), expected);
        assert_eq!(full.verification_method(), expected);
    }

    /// A method belonging to a *different* DID would name a key the gateway's
    /// own document does not declare, so it is refused rather than signed with.
    #[test]
    fn a_verification_method_from_another_did_is_refused() {
        let err = ControlKey::from_seed([5u8; 32])
            .with_stable_did(WEBVH.to_string(), Some("did:webvh:QmOther:elsewhere.example#key-1".to_string()))
            .err()
            .map(|e| format!("{e:?}"))
            .expect("a foreign verification method must be refused");
        assert!(err.contains("does not belong to"), "{err}");
    }

    /// The update key is the crown jewel — it can re-point verification
    /// methods, so holding it would let a compromised request-serving gateway
    /// rewrite its own identity. There is deliberately no way to give it one:
    /// `ControlKey` carries exactly one signing key, and applying a stable
    /// identifier does not add another.
    #[test]
    fn a_stable_identifier_adds_no_update_key() {
        let key = ControlKey::from_seed([6u8; 32])
            .with_stable_did(WEBVH.to_string(), None)
            .expect("stable identifier");
        // The signing key is unchanged by naming: same key, different label.
        assert_eq!(
            key.public_key_multibase(),
            ControlKey::from_seed([6u8; 32]).public_key_multibase(),
            "applying an identifier must not change or add key material"
        );
        assert!(!format!("{key:?}").contains("update"), "no update key is held, so none can be named");
    }
}
