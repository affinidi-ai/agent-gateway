use std::borrow::Cow;
use std::sync::Arc;

use affinidi_data_integrity::DataIntegrityError;
use affinidi_data_integrity::signer::Signer as DiSigner;
use affinidi_secrets_resolver::secrets::KeyType;
use async_trait::async_trait;
use ssi::crypto::algorithm::{Algorithm, AlgorithmInstance, SignatureAlgorithmType};
use ssi::verification_methods::{MessageSigner, Signer, VerificationMethod};
use ssi_claims_core::{MessageSignatureError, SignatureError};
use zeroize::Zeroizing;

/// An `ssi` signer whose Ed25519 signatures are made by the in-process VTA
/// library instead of by the key material directly. Wrap it in
/// `ssi::verification_methods::LocalSigner` where the suite wants one.
pub struct VtaSsiSigner {
    secret: Arc<Zeroizing<[u8; 32]>>,
}

impl VtaSsiSigner {
    pub fn new(secret: Zeroizing<[u8; 32]>) -> Self {
        Self { secret: Arc::new(secret) }
    }
}

impl<M: VerificationMethod> Signer<M> for VtaSsiSigner {
    type MessageSigner = VtaMessageSigner;

    async fn for_method(
        &self,
        _method: Cow<'_, M>,
    ) -> Result<Option<Self::MessageSigner>, SignatureError> {
        Ok(Some(VtaMessageSigner {
            secret: Arc::clone(&self.secret),
        }))
    }
}

/// A `did:webvh` log signer whose Ed25519 signatures are made by the in-process
/// VTA library. Its verification method is the key's own `did:key`, which is
/// what the log's `update_keys` name.
pub struct VtaDiSigner {
    secret: Zeroizing<[u8; 32]>,
    verification_method: String,
    public_multibase: String,
}

impl VtaDiSigner {
    pub fn from_seed(secret: Zeroizing<[u8; 32]>) -> Self {
        let public = ed25519_dalek::SigningKey::from_bytes(&secret)
            .verifying_key()
            .to_bytes();
        let mut prefixed = vec![0xed, 0x01];
        prefixed.extend_from_slice(&public);
        let public_multibase = multibase::encode(multibase::Base::Base58Btc, prefixed);
        Self {
            secret,
            verification_method: format!("did:key:{public_multibase}#{public_multibase}"),
            public_multibase,
        }
    }

    /// From the private JWK of an Ed25519 key.
    pub fn from_jwk(jwk: &serde_json::Value) -> Result<Self, super::VtaError> {
        let key: ssi::jwk::JWK = serde_json::from_value(jwk.clone())
            .map_err(|e| super::VtaError::Signing(format!("local signing: not a JWK: {e}")))?;
        Ok(Self::from_seed(super::secret_of(&key)?))
    }

    /// The key's public half as a multibase string (`z6Mk…`).
    pub fn public_multibase(&self) -> &str {
        &self.public_multibase
    }
}

#[async_trait]
impl DiSigner for VtaDiSigner {
    fn key_type(&self) -> KeyType {
        KeyType::Ed25519
    }

    fn verification_method(&self) -> &str {
        &self.verification_method
    }

    async fn sign(
        &self,
        data: &[u8],
    ) -> Result<Vec<u8>, DataIntegrityError> {
        let signature = super::shared()
            .await
            .map_err(DataIntegrityError::signing)?
            .sign_raw(&self.secret, data)
            .await
            .map_err(DataIntegrityError::signing)?;
        Ok(signature.to_vec())
    }
}

pub struct VtaMessageSigner {
    secret: Arc<Zeroizing<[u8; 32]>>,
}

impl<A: SignatureAlgorithmType> MessageSigner<A> for VtaMessageSigner
where
    A::Instance: Into<AlgorithmInstance>,
{
    async fn sign(
        self,
        algorithm: A::Instance,
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        let algorithm = algorithm.into().algorithm();
        if algorithm != Algorithm::EdDSA {
            return Err(MessageSignatureError::UnsupportedAlgorithm(algorithm.to_string()));
        }
        let signature = super::shared()
            .await
            .map_err(MessageSignatureError::signature_failed)?
            .sign_raw(&self.secret, message)
            .await
            .map_err(MessageSignatureError::signature_failed)?;
        Ok(signature.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use ssi::jwk::JWK;

    use super::*;

    fn signer_for(key: &JWK) -> VtaMessageSigner {
        VtaMessageSigner {
            secret: Arc::new(super::super::secret_of(key).expect("secret")),
        }
    }

    #[tokio::test]
    async fn the_vta_signs_exactly_the_bytes_the_key_signed_before() {
        let key = JWK::generate_ed25519().expect("key");
        let message = b"canonical hash data the suite produced";

        let through_the_vta = MessageSigner::<Algorithm>::sign(signer_for(&key), AlgorithmInstance::EdDSA, message)
            .await
            .expect("signed by the vta");
        let directly = MessageSigner::<Algorithm>::sign(key.clone(), AlgorithmInstance::EdDSA, message)
            .await
            .expect("signed by the key");

        assert_eq!(through_the_vta, directly);
        assert_eq!(through_the_vta.len(), 64);
    }

    #[tokio::test]
    async fn a_log_signer_names_the_keys_own_did_key_and_signs_what_the_key_signed_before() {
        use affinidi_secrets_resolver::secrets::Secret;

        let jwk = serde_json::to_value(JWK::generate_ed25519().expect("key")).expect("jwk");
        let signer = VtaDiSigner::from_jwk(&jwk).expect("signer");
        let secret = Secret::from_jwk_value("did:key:temp#temp", &jwk).expect("secret");

        let expected_multibase = secret
            .get_public_keymultibase()
            .expect("multibase");
        assert_eq!(signer.public_multibase(), expected_multibase);
        assert_eq!(
            DiSigner::verification_method(&signer),
            format!("did:key:{expected_multibase}#{expected_multibase}")
        );
        assert_eq!(DiSigner::key_type(&signer), KeyType::Ed25519);

        let data = b"entry hash and update keys";
        assert_eq!(
            DiSigner::sign(&signer, data)
                .await
                .expect("by the vta"),
            DiSigner::sign(&secret, data)
                .await
                .expect("by the key")
        );
    }

    #[test]
    fn a_value_that_is_not_an_ed25519_private_key_is_refused() {
        assert!(VtaDiSigner::from_jwk(&serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": "AA"})).is_err());
        assert!(VtaDiSigner::from_jwk(&serde_json::json!("nope")).is_err());
    }

    #[tokio::test]
    async fn an_algorithm_other_than_eddsa_is_refused_not_signed() {
        let key = JWK::generate_ed25519().expect("key");

        let refused = MessageSigner::<Algorithm>::sign(signer_for(&key), AlgorithmInstance::ES256, b"m").await;

        assert!(matches!(refused, Err(MessageSignatureError::UnsupportedAlgorithm(_))), "{refused:?}");
    }
}
