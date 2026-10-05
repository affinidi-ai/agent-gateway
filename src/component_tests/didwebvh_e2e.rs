#![cfg(feature = "didwebvh")]

use std::sync::Arc;

use serde_json::json;
use tempfile::TempDir;

use crate::identity::didwebvh::create::{create_webvh_did, strip_jwk_private_key};
use crate::identity::didwebvh::resolver::DidWebvhResolver;
use crate::storage::{DidLogStorage, FileDidLogStorage};

#[tokio::test(flavor = "multi_thread")]
async fn signed_didwebvh_log_roundtrip_resolves_from_raw_storage() {
    let temp_dir = TempDir::new().expect("temp dir must be created");
    let storage = Arc::new(FileDidLogStorage::new(
        temp_dir
            .path()
            .join("did_logs"),
    )) as Arc<dyn DidLogStorage>;

    let key_pair = crate::identity::didwebvh::generate_ed25519_keypair().expect("ed25519 keypair must be created");
    let placeholder_did = "did:webvh:{SCID}:example.com:agents:resolver-roundtrip";
    let did_document = json!({
        "id": placeholder_did,
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{}#key-1", placeholder_did),
            "type": "JsonWebKey2020",
            "controller": placeholder_did,
            "publicKeyJwk": strip_jwk_private_key(&key_pair.public_key)
        }],
        "authentication": [format!("{}#key-1", placeholder_did)],
        "assertionMethod": [format!("{}#key-1", placeholder_did)]
    });

    let created = create_webvh_did(&key_pair.private_key, did_document, "https://example.com/")
        .await
        .expect("did:webvh creation must succeed");

    storage
        .append_raw(&created.final_did, &created.log_entry_json)
        .await
        .expect("birth log must be stored as raw json");

    let raw_entries = storage
        .load_all_raw(&created.final_did)
        .await
        .expect("raw log must be loaded");
    assert_eq!(raw_entries, vec![created.log_entry_json.clone()]);

    let resolver = DidWebvhResolver::new(storage.clone());
    resolver
        .verify_log_raw_for_integration_test(&created.final_did, &raw_entries)
        .await
        .expect("library validation must accept the signed raw log");

    let resolved = resolver
        .resolve(&created.final_did)
        .await
        .expect("resolver must load the stored did:webvh document");

    assert_eq!(resolved.id.as_str(), created.final_did);
}
