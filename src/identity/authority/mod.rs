//! Credential/token *issuing authority* port (VTA-01).
//!
//! The gateway signs STS access tokens / ID-JAGs, payment-receipt presentations
//! and AP2 presentations with its local Ed25519 *issuer* key (owned by
//! [`VCIssuer`]). To let a Verifiable Trust Agent (VTA) take over those
//! private-key operations in later tickets of the VTA-integration epic, every
//! such caller goes through the [`CredentialAuthority`] port instead of binding
//! to `VCIssuer` directly.
//!
//! This ticket (VTA-01) ships **only** the local implementation
//! ([`LocalCredentialAuthority`]), which delegates to the in-process `VCIssuer`
//! and is therefore byte-for-byte identical to the previous behaviour — no wire
//! format or functional change. A `VtaCredentialAuthority` that dispatches the
//! `keys/sign-jws/0.1` Trust Task lands in VTA-02 and later.
//!
//! Verification stays local by design and is deliberately **not** part of this
//! port — a VTA is an *issuing* authority, not a verifier (see epic VTA-08).

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::identity::VCIssuer;

/// The gateway's credential/token issuing authority: the private-key operations
/// — sign a JWT with the issuer key, report the issuer DID and public JWKS —
/// that a VTA will later perform on the gateway's behalf.
#[async_trait]
pub trait CredentialAuthority: Send + Sync {
    /// DID of the issuer whose key signs tokens (the gateway `proxy_did` today).
    async fn issuer_did(&self) -> Result<String>;

    /// Public JWKS (private `d` component stripped) for verifying
    /// issuer-signed JWTs without resolving the issuer DID document.
    async fn issuer_jwks(&self) -> Result<Value>;

    /// Sign `claims` into a compact JWS (JWT) with the issuer key.
    async fn sign_token(
        &self,
        claims: &Value,
    ) -> Result<String>;

    /// Sign `claims` into a compact JWS carrying an explicit JOSE `typ` header
    /// (e.g. `oauth-id-jag+jwt`), so a verifier can reject a token presented in
    /// the wrong context (RFC 8725 explicit typing).
    async fn sign_token_typ(
        &self,
        claims: &Value,
        typ: &str,
    ) -> Result<String>;
}

/// [`CredentialAuthority`] backed by the in-process [`VCIssuer`] (gateway
/// Ed25519 key). This is the default implementation and preserves today's
/// behaviour exactly — it only forwards to existing `VCIssuer` methods.
pub struct LocalCredentialAuthority {
    issuer: Arc<VCIssuer>,
}

impl LocalCredentialAuthority {
    pub fn new(issuer: Arc<VCIssuer>) -> Self {
        Self { issuer }
    }
}

#[async_trait]
impl CredentialAuthority for LocalCredentialAuthority {
    async fn issuer_did(&self) -> Result<String> {
        self.issuer
            .get_issuer_did()
            .await
    }

    async fn issuer_jwks(&self) -> Result<Value> {
        self.issuer
            .signing_public_jwks()
            .await
    }

    async fn sign_token(
        &self,
        claims: &Value,
    ) -> Result<String> {
        self.issuer
            .sign_jwt_with_gateway_key(claims)
            .await
    }

    async fn sign_token_typ(
        &self,
        claims: &Value,
        typ: &str,
    ) -> Result<String> {
        self.issuer
            .sign_jwt_with_gateway_key_typ(claims, typ)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::json;

    async fn local_authority() -> (LocalCredentialAuthority, Arc<VCIssuer>, tempfile::TempDir) {
        let (issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);
        (LocalCredentialAuthority::new(Arc::clone(&issuer)), issuer, temp_dir)
    }

    fn decode_jwt_header(jwt: &str) -> Value {
        let header_b64 = jwt
            .split('.')
            .next()
            .expect("jwt has a header segment");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .expect("header is valid base64url");
        serde_json::from_slice(&bytes).expect("header is valid JSON")
    }

    #[tokio::test]
    async fn issuer_did_matches_wrapped_issuer() {
        let (authority, issuer, _tmp) = local_authority().await;
        let via_port = authority
            .issuer_did()
            .await
            .expect("issuer_did via port");
        let direct = issuer
            .get_issuer_did()
            .await
            .expect("issuer_did direct");
        assert_eq!(via_port, direct);
        assert!(via_port.starts_with("did:"), "issuer DID is a DID: {via_port}");
    }

    #[tokio::test]
    async fn issuer_jwks_matches_wrapped_issuer() {
        let (authority, issuer, _tmp) = local_authority().await;
        let via_port = authority
            .issuer_jwks()
            .await
            .expect("issuer_jwks via port");
        let direct = issuer
            .signing_public_jwks()
            .await
            .expect("signing_public_jwks direct");
        assert_eq!(via_port, direct);
        // The projected JWKS must never leak the private component.
        let key = &via_port["keys"][0];
        assert!(key.get("d").is_none(), "public JWKS must not contain private 'd'");
        assert_eq!(key["use"], json!("sig"));
    }

    #[tokio::test]
    async fn sign_token_is_byte_identical_to_direct_signing() {
        let (authority, issuer, _tmp) = local_authority().await;
        let claims = json!({ "iss": "did:example:gw", "sub": "agent-1", "aud": "svc" });
        let via_port = authority
            .sign_token(&claims)
            .await
            .expect("sign_token via port");
        let direct = issuer
            .sign_jwt_with_gateway_key(&claims)
            .await
            .expect("sign_jwt_with_gateway_key direct");
        // Ed25519 over a verbatim payload is deterministic (RFC 8032), so the
        // port must reproduce the pre-seam output byte-for-byte.
        assert_eq!(via_port, direct);
        assert_eq!(via_port.split('.').count(), 3, "compact JWS has three segments");
        assert_eq!(decode_jwt_header(&via_port)["typ"], json!("JWT"));
    }

    #[tokio::test]
    async fn sign_token_typ_sets_explicit_typ_and_is_byte_identical() {
        let (authority, issuer, _tmp) = local_authority().await;
        let claims = json!({ "iss": "did:example:gw", "sub": "agent-1" });
        let via_port = authority
            .sign_token_typ(&claims, "oauth-id-jag+jwt")
            .await
            .expect("sign_token_typ via port");
        let direct = issuer
            .sign_jwt_with_gateway_key_typ(&claims, "oauth-id-jag+jwt")
            .await
            .expect("sign_jwt_with_gateway_key_typ direct");
        assert_eq!(via_port, direct);
        assert_eq!(decode_jwt_header(&via_port)["typ"], json!("oauth-id-jag+jwt"));
    }
}
