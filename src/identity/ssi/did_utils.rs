use anyhow::Result;
use did_peer::{DIDPeer, DIDPeerCreateKeys, DIDPeerKeys};
use ssi::jwk::JWK as SsiJwk;

pub fn jwk_to_multibase_ed25519(jwk: &SsiJwk) -> Result<String> {
    let public_key = jwk.to_public();

    let x = match &public_key.params {
        ssi::jwk::Params::OKP(okp) => &okp.public_key.0,
        _ => anyhow::bail!("Expected OKP key type for Ed25519"),
    };

    let ed25519_multicodec_prefix: [u8; 2] = [0xed, 0x01];
    let mut multicodec_bytes = Vec::with_capacity(2 + x.len());
    multicodec_bytes.extend_from_slice(&ed25519_multicodec_prefix);
    multicodec_bytes.extend_from_slice(x);

    Ok(multibase::encode(multibase::Base::Base58Btc, multicodec_bytes))
}

#[allow(dead_code)]
pub fn create_did_peer_from_ed25519_jwk(jwk: &SsiJwk) -> Result<String> {
    let public_key_multibase = jwk_to_multibase_ed25519(jwk)?;

    let keys = vec![DIDPeerCreateKeys {
        purpose: DIDPeerKeys::Verification,
        type_: None,
        public_key_multibase: Some(public_key_multibase),
    }];

    let (did_peer, _) =
        DIDPeer::create_peer_did(&keys, None).map_err(|e| anyhow::anyhow!("Failed to create did:peer: {:?}", e))?;

    Ok(did_peer)
}

/// A did:peer whose document carries the same Ed25519 key twice, so the
/// `#key-2` verification method the local VC/VP signers reference resolves.
#[cfg(test)]
pub fn create_signing_did_peer(jwk: &SsiJwk) -> Result<String> {
    let public_key_multibase = jwk_to_multibase_ed25519(jwk)?;

    let keys = vec![
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Verification,
            type_: None,
            public_key_multibase: Some(public_key_multibase.clone()),
        },
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Verification,
            type_: None,
            public_key_multibase: Some(public_key_multibase),
        },
    ];

    let (did_peer, _) =
        DIDPeer::create_peer_did(&keys, None).map_err(|e| anyhow::anyhow!("Failed to create did:peer: {:?}", e))?;

    Ok(did_peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_did_peer_from_jwk() {
        let jwk = crate::identity::test_helpers::test_signing_key();

        let did_peer = create_did_peer_from_ed25519_jwk(&jwk).unwrap();

        assert!(did_peer.starts_with("did:peer:2.V"));

        let multibase = jwk_to_multibase_ed25519(&jwk).unwrap();
        assert!(multibase.starts_with("z6Mk"));
    }

    #[test]
    fn test_multibase_format() {
        let jwk = crate::identity::test_helpers::test_signing_key().to_public();

        let multibase = jwk_to_multibase_ed25519(&jwk).unwrap();
        assert!(multibase.starts_with("z"));
        assert!(multibase.len() > 40);
    }
}
