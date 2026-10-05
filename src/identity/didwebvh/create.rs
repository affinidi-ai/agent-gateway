use affinidi_tdk_common::secrets_resolver::secrets::{Secret, SecretMaterial};
use anyhow::Result;
use didwebvh_rs::prelude::{CreateDIDConfig, Parameters, create_did};

use super::types::LogEntry;

pub struct WebVhCreateResult {
    pub final_did: String,
    pub scid: String,
    pub log_entry_json: String,
    pub signed_entry: LogEntry,
    pub multibase_pubkey: String,
}

pub(crate) fn strip_jwk_private_key(jwk: &serde_json::Value) -> serde_json::Value {
    let mut pub_jwk = jwk.clone();
    if let Some(obj) = pub_jwk.as_object_mut() {
        obj.remove("d");
    }
    pub_jwk
}

pub(crate) fn extract_public_jwk(secret: &Secret) -> Result<serde_json::Value> {
    let jwk_value = match &secret.secret_material {
        SecretMaterial::JWK(jwk) => {
            serde_json::to_value(jwk).map_err(|e| anyhow::anyhow!("Failed to serialize JWK: {}", e))?
        }
        _ => return Err(anyhow::anyhow!("Secret is not a JWK")),
    };
    Ok(strip_jwk_private_key(&jwk_value))
}

pub(crate) async fn create_webvh_did(
    ed25519_private_jwk: &serde_json::Value,
    did_document: serde_json::Value,
    base_url: &str,
) -> Result<WebVhCreateResult> {
    let temp_key_id = "did:key:temp#temp".to_string();
    let raw_secret = didwebvh_rs::prelude::Secret::from_str(&temp_key_id, ed25519_private_jwk)
        .map_err(|e| anyhow::anyhow!("Failed to convert Ed25519 key to Secret: {}", e))?;
    let multibase_pubkey = raw_secret
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get multibase public key: {}", e))?;
    let did_key_id = format!("did:key:{0}#{0}", multibase_pubkey);
    let mut auth_secret = didwebvh_rs::prelude::Secret::from_str(&did_key_id, ed25519_private_jwk)
        .map_err(|e| anyhow::anyhow!("Failed to build auth secret: {}", e))?;
    auth_secret.id = did_key_id;

    let parameters = Parameters {
        update_keys: Some(std::sync::Arc::new(vec![didwebvh_rs::Multibase::new(multibase_pubkey.clone())])),
        ..Default::default()
    };

    let normalized_base = format!("{}/", base_url.trim_end_matches('/'));
    let create_result = create_did(
        CreateDIDConfig::builder()
            .address(normalized_base)
            .authorization_key(auth_secret)
            .did_document(did_document)
            .parameters(parameters)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build CreateDIDConfig: {}", e))?,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create DID: {}", e))?;

    let final_did = create_result
        .did()
        .to_string();
    let scid = super::identifier::parse_did_webvh(&final_did)?
        .scid
        .ok_or_else(|| anyhow::anyhow!("created did:webvh is missing SCID: {}", final_did))?;

    let log_entry_json = serde_json::to_string(create_result.log_entry())
        .map_err(|e| anyhow::anyhow!("Failed to serialize log entry: {}", e))?;
    let signed_entry: LogEntry =
        serde_json::from_str(&log_entry_json).map_err(|e| anyhow::anyhow!("Failed to deserialize log entry: {}", e))?;

    Ok(WebVhCreateResult {
        final_did,
        scid,
        log_entry_json,
        signed_entry,
        multibase_pubkey,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_jwk_private_key_removes_d() {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "test_public_value",
            "d": "test_private_value"
        });
        let public = strip_jwk_private_key(&jwk);
        assert!(public.get("d").is_none());
        assert_eq!(
            public
                .get("kty")
                .unwrap()
                .as_str()
                .unwrap(),
            "OKP"
        );
        assert_eq!(
            public
                .get("crv")
                .unwrap()
                .as_str()
                .unwrap(),
            "Ed25519"
        );
        assert_eq!(
            public
                .get("x")
                .unwrap()
                .as_str()
                .unwrap(),
            "test_public_value"
        );
    }

    #[test]
    fn strip_jwk_private_key_noop_when_no_d() {
        let jwk = serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": "val"});
        let public = strip_jwk_private_key(&jwk);
        assert_eq!(public, jwk);
    }

    #[test]
    fn create_result_scid_parser_requires_scid_segment() {
        let result = super::super::identifier::parse_did_webvh("did:webvh:example.com:agents:alpha")
            .expect("legacy did should still parse");

        assert!(result.scid.is_none());
    }
}
