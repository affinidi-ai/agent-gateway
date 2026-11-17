//! Signing *as a VTA context* — for artifacts whose verifier resolves the
//! claimed DID rather than a published JWKS.
//!
//! [`crate::vta::authority::VtaCredentialAuthority`] signs tokens that claim
//! the trust agent's DID while using a key held in the gateway's context. That
//! split is fine for STS tokens, which verifiers check against the JWKS the
//! gateway publishes. It is **fatal** for the fabric issuer attestation, whose
//! verifier resolves the claimed `iss` and requires the signing key to be
//! declared in *that* document — a key in the gateway's context is not in the
//! trust agent's document, so every peer would reject it.
//!
//! This signs as the context itself: the claimed DID is the context's own
//! `did:key`, which declares exactly the key that signs it, by construction.
//! One party, one key, resolvable by anyone with no hosting and no registry.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::vta::client::VtaRestClient;
use crate::vta::context_identity::ContextIdentityResolver;

/// Signs artifacts that must be attributable to a DID a verifier can resolve.
#[async_trait]
pub trait ContextSigner: Send + Sync {
    /// The DID the signature should claim.
    async fn issuer_did(&self) -> Result<String>;

    /// Sign `claims` into a compact JWS with an explicit JOSE `typ`.
    async fn sign_typ(
        &self,
        claims: &Value,
        typ: &str,
    ) -> Result<String>;
}

/// Signs as a VTA context, using the key that backs the context's DID.
pub struct VtaContextSigner {
    context: ContextIdentityResolver,
}

impl VtaContextSigner {
    pub fn new(
        client: Arc<VtaRestClient>,
        context_id: String,
    ) -> Self {
        Self {
            context: ContextIdentityResolver::new(client, context_id),
        }
    }
}

#[async_trait]
impl ContextSigner for VtaContextSigner {
    async fn issuer_did(&self) -> Result<String> {
        Ok(self
            .context
            .identity()
            .await?
            .did)
    }

    async fn sign_typ(
        &self,
        claims: &Value,
        typ: &str,
    ) -> Result<String> {
        self.context
            .sign_jws(claims, typ)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vta::control_key::ControlKey;
    use serde_json::json;
    use std::time::Duration;

    fn signer(context_id: &str) -> VtaContextSigner {
        let client = Arc::new(
            VtaRestClient::new(
                "http://127.0.0.1:1",
                "did:webvh:vta.example",
                Arc::new(ControlKey::from_seed([9u8; 32])),
                Duration::from_millis(50),
                1,
                None,
            )
            .expect("build client"),
        );
        VtaContextSigner::new(client, context_id.to_string())
    }

    /// The attestation names the context DID's own verification method and is
    /// signed by the key that backs that DID — what a peer resolving the claimed
    /// issuer needs in order to accept it.
    #[tokio::test]
    async fn the_attestation_is_signed_by_the_key_behind_the_context_did() {
        use crate::vta::context_identity::mock::MockContextVta;

        let vta = MockContextVta::new("gw", "gw-issuer");
        let url = vta.spawn().await;
        let signer = VtaContextSigner::new(vta.client(&url), "gw".to_string());

        assert_eq!(
            signer
                .issuer_did()
                .await
                .unwrap(),
            vta.did()
        );
        let jws = signer
            .sign_typ(&json!({ "sub": "x" }), "gateway-issuer-attestation+jwt")
            .await
            .expect("signed");

        let header = jws.split('.').next().unwrap();
        let header: Value = serde_json::from_slice(
            &base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, header).unwrap(),
        )
        .unwrap();
        assert_eq!(header["kid"], json!(vta.verification_method()));
        assert_eq!(header["typ"], json!("gateway-issuer-attestation+jwt"));
        let sent = vta
            .last_sign_request
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(sent["keyId"], json!("gw-issuer"));
    }

    /// An unreachable agent is an error, never a fallback to a local key: the
    /// whole point is that the claimed DID and the signing key are the same
    /// party, and a local signature would break exactly that.
    #[tokio::test]
    async fn an_unreachable_agent_surfaces_rather_than_falling_back() {
        let signer = signer("gw");
        assert!(
            signer
                .issuer_did()
                .await
                .is_err()
        );
        assert!(
            signer
                .sign_typ(&json!({ "sub": "x" }), "test+jwt")
                .await
                .is_err()
        );
    }
}
