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

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::RwLock;

use crate::vta::client::VtaRestClient;

/// `vta/contexts/get/1.0`.
const TASK_CONTEXTS_GET: &str = "https://trusttasks.org/spec/vta/contexts/get/1.0";

/// `keys/sign-jws/0.1`.
const TASK_KEYS_SIGN_JWS: &str = "https://trusttasks.org/spec/keys/sign-jws/0.1";

/// The JOSE algorithm the context's `did:key` signs with. The VTA echoes the
/// algorithm it chose; the gateway checks it so an attestation it attributes to
/// the context DID cannot have been made under a different one.
const SIGNING_ALGORITHM: &str = "EdDSA";

/// The `keys/sign-jws` result. `alg` and `keyId` are echoed by the VTA and
/// verified before the signature is attributed to the context DID.
#[derive(Debug, Deserialize)]
struct SignJwsResult {
    jws: String,
    alg: String,
    #[serde(rename = "keyId")]
    key_id: String,
}

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

/// The context's DID and the key it designates.
#[derive(Debug, Clone)]
struct ContextIdentity {
    did: String,
    key_id: String,
}

/// Signs as a VTA context, using the key that context designates.
pub struct VtaContextSigner {
    client: Arc<VtaRestClient>,
    context_id: String,
    /// Resolved once and reused. The pair is immutable in practice — the
    /// provisioning path that sets them is write-once — so re-reading it per
    /// signature would add a round trip for a value that cannot change.
    identity: RwLock<Option<ContextIdentity>>,
}

impl VtaContextSigner {
    pub fn new(
        client: Arc<VtaRestClient>,
        context_id: String,
    ) -> Self {
        Self {
            client,
            context_id,
            identity: RwLock::new(None),
        }
    }

    /// The context's DID and designated key, read once.
    async fn identity(&self) -> Result<ContextIdentity> {
        if let Some(identity) = self
            .identity
            .read()
            .await
            .as_ref()
        {
            return Ok(identity.clone());
        }

        let response = self
            .client
            .dispatch_signed::<Value>(TASK_CONTEXTS_GET, json!({ "id": self.context_id }))
            .await
            .map_err(|e| anyhow!("reading context `{}` to sign as it: {e}", self.context_id))?;
        let record = response
            .get("payload")
            .unwrap_or(&response);

        let did = record
            .get("did")
            .and_then(|d| d.as_str())
            .ok_or_else(|| {
                anyhow!("context `{}` has no DID, so nothing it signs would be attributable", self.context_id)
            })?
            .to_string();
        let key_id = record
            .get("issuerKeyId")
            .or_else(|| record.get("issuer_key_id"))
            .and_then(|k| k.as_str())
            .ok_or_else(|| anyhow!("context `{}` designates no signing key", self.context_id))?
            .to_string();

        let identity = ContextIdentity { did, key_id };
        *self.identity.write().await = Some(identity.clone());
        Ok(identity)
    }
}

#[async_trait]
impl ContextSigner for VtaContextSigner {
    async fn issuer_did(&self) -> Result<String> {
        Ok(self.identity().await?.did)
    }

    async fn sign_typ(
        &self,
        claims: &Value,
        typ: &str,
    ) -> Result<String> {
        let identity = self.identity().await?;
        // `kid` is the context DID's own verification method. A `did:key`
        // document declares exactly one, whose id is the DID plus its own
        // multibase fragment — so naming it keeps a verifier from having to
        // guess, and a verifier that ignores `kid` still lands on the same key.
        let kid = format!(
            "{}#{}",
            identity.did,
            identity
                .did
                .strip_prefix("did:key:")
                .unwrap_or(&identity.key_id)
        );
        let request = json!({
            "keyId": identity.key_id,
            "header": { "typ": typ, "kid": kid },
            "payload": claims,
        });
        let response: SignJwsResult = self
            .client
            .dispatch_signed(TASK_KEYS_SIGN_JWS, request)
            .await
            .map_err(|e| anyhow!("signing as context `{}`: {e}", self.context_id))?;
        // Fail closed on attribution: a peer resolves the claimed DID and
        // demands the signing key be declared there, so the VTA must have used
        // exactly the key this context designates, under its algorithm.
        if response.key_id != identity.key_id {
            return Err(anyhow!(
                "signing as context `{}`: VTA echoed key `{}` but `{}` was requested",
                self.context_id,
                response.key_id,
                identity.key_id
            ));
        }
        if response.alg != SIGNING_ALGORITHM {
            return Err(anyhow!(
                "signing as context `{}`: VTA signed with `{}`; the context key uses `{SIGNING_ALGORITHM}`",
                self.context_id,
                response.alg
            ));
        }
        Ok(response.jws)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vta::control_key::ControlKey;
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
