use cucumber::{given, then, when};
use serde_json::{Value, json};
use std::path::Path;

use crate::bdd_support::admin_client::RecordedResponse;
use crate::bdd_support::http::collect_headers;
use crate::steps::when::ensure_gateway_running;
use crate::world::SurfaceWorld;

const SIGNING_KEY_FRAGMENT: &str = "#key-2";
const LEGACY_GATEWAY_DID: &str = "did:web:localhost";

#[given("the gateway published its DID document without its signing key under assertionMethod")]
fn gateway_did_published_without_signing_key(world: &mut SurfaceWorld) {
    world.gateway_did_without_assertion_multikey = true;
}

/// Writes the issuer files of a `did:web` gateway whose DID document publishes its signing
/// Multikey but lists only `#key-1` under `assertionMethod`, as gateways wrote it before the
/// Multikey was listed. On start the gateway moves that document into its `did:webvh` log.
pub(crate) fn seed_gateway_did_without_assertion_multikey(vc_keys: &Path) {
    use affinidi_tdk_common::secrets_resolver::secrets::Secret;

    std::fs::create_dir_all(vc_keys).expect("create the vc_keys directory");
    let signing_key = ssi::jwk::JWK::generate_ed25519().expect("generate the gateway signing key");
    let signing_key_json = serde_json::to_value(&signing_key).expect("serialize the gateway signing key");
    let multikey = didwebvh_rs::prelude::Secret::from_str("did:key:seed#seed", &signing_key_json)
        .expect("read the gateway signing key")
        .get_public_keymultibase()
        .expect("encode the gateway signing key as a Multikey");
    let x25519 = Secret::generate_x25519(Some(&format!("{LEGACY_GATEWAY_DID}#key-x25519-1")), None)
        .expect("generate the key agreement key");
    let p256 = Secret::generate_p256(Some(&format!("{LEGACY_GATEWAY_DID}#key-p256-1")), None)
        .expect("generate the key agreement key");

    let public_jwk = |secret: &Secret| {
        let mut jwk = serde_json::to_value(secret).expect("serialize the key agreement key")["privateKeyJwk"].clone();
        jwk.as_object_mut()
            .expect("the key agreement key is a JWK")
            .remove("d");
        jwk
    };
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": LEGACY_GATEWAY_DID,
        "verificationMethod": [
            {
                "id": format!("{LEGACY_GATEWAY_DID}#key-1"),
                "type": "JsonWebKey2020",
                "controller": LEGACY_GATEWAY_DID,
                "publicKeyJwk": signing_key.to_public()
            },
            {
                "id": format!("{LEGACY_GATEWAY_DID}{SIGNING_KEY_FRAGMENT}"),
                "type": "Multikey",
                "controller": LEGACY_GATEWAY_DID,
                "publicKeyMultibase": multikey
            },
            {
                "id": x25519.id,
                "type": "JsonWebKey2020",
                "controller": LEGACY_GATEWAY_DID,
                "publicKeyJwk": public_jwk(&x25519)
            },
            {
                "id": p256.id,
                "type": "JsonWebKey2020",
                "controller": LEGACY_GATEWAY_DID,
                "publicKeyJwk": public_jwk(&p256)
            }
        ],
        "authentication": [format!("{LEGACY_GATEWAY_DID}#key-1")],
        "assertionMethod": [format!("{LEGACY_GATEWAY_DID}#key-1")],
        "keyAgreement": [x25519.id, p256.id]
    });

    let write = |name: &str, value: String| {
        std::fs::write(vc_keys.join(name), value).unwrap_or_else(|e| panic!("write {name}: {e}"));
    };
    write(
        "issuer_config.json",
        json!({
            "proxy_did": LEGACY_GATEWAY_DID,
            "signing_key": signing_key_json,
            "is_vp_challenge_required": false
        })
        .to_string(),
    );
    write("x25519_key.json", serde_json::to_string(&x25519).expect("serialize the key agreement key"));
    write("p256_key.json", serde_json::to_string(&p256).expect("serialize the key agreement key"));
    write("did.json", document.to_string());
}

#[when("the caller fetches the gateway DID log")]
async fn gateway_did_log_fetched(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;

    let infra = world
        .infra
        .as_ref()
        .expect("scenario infra must exist");
    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/.well-known/did.jsonl", infra.gateway_port))
        .send()
        .await
        .expect("fetch gateway DID log");

    world.sent_body = None;
    let status = response.status().as_u16();
    let headers = collect_headers(response.headers());
    let body = Value::String(
        response
            .text()
            .await
            .expect("read gateway DID log"),
    );
    world.caller_response = Some(RecordedResponse { status, headers, body });
}

fn response_body(world: &SurfaceWorld) -> &Value {
    &world
        .caller_response
        .as_ref()
        .expect("caller_response must be set")
        .body
}

fn did_log_versions(world: &SurfaceWorld) -> Vec<Value> {
    response_body(world)
        .as_str()
        .expect("the gateway DID log was fetched")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("each gateway DID log line is JSON"))
        .collect()
}

fn lists_signing_key_for_assertions(document: &Value) -> bool {
    let did = document["id"]
        .as_str()
        .expect("the DID document names its DID");
    let signing_key_id = format!("{did}{SIGNING_KEY_FRAGMENT}");
    let publishes_multikey = document["verificationMethod"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|method| method["id"] == signing_key_id.as_str() && method["type"] == "Multikey");
    assert!(publishes_multikey, "the DID document must publish {signing_key_id} as a Multikey: {document}");
    document["assertionMethod"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|id| *id == signing_key_id.as_str())
}

#[then("the DID document lists the gateway signing key under assertionMethod")]
fn did_document_lists_signing_key(world: &mut SurfaceWorld) {
    let document = response_body(world);
    assert!(lists_signing_key_for_assertions(document), "assertionMethod must list the signing key: {document}");
}

#[then(expr = "the gateway DID log has {int} version(s)")]
fn gateway_did_log_has_versions(
    world: &mut SurfaceWorld,
    count: usize,
) {
    assert_eq!(did_log_versions(world).len(), count);
}

#[then("every version of the gateway DID log describes the same did:webvh DID")]
fn gateway_did_log_keeps_its_did(world: &mut SurfaceWorld) {
    let versions = did_log_versions(world);
    let did = versions[0]["state"]["id"]
        .as_str()
        .expect("the first version names its DID");
    assert!(did.starts_with("did:webvh:"), "the gateway DID must be a did:webvh DID, got {did}");
    for version in &versions {
        assert_eq!(version["state"]["id"], did, "every version must describe {did}");
    }
}

#[then("the first version of the gateway DID log does not list the gateway signing key under assertionMethod")]
fn first_version_lacks_signing_key(world: &mut SurfaceWorld) {
    let versions = did_log_versions(world);
    assert!(!lists_signing_key_for_assertions(&versions[0]["state"]));
}

#[then("the latest version of the gateway DID log lists the gateway signing key under assertionMethod")]
fn latest_version_lists_signing_key(world: &mut SurfaceWorld) {
    let versions = did_log_versions(world);
    let latest = versions
        .last()
        .expect("the gateway DID log has a version");
    assert!(lists_signing_key_for_assertions(&latest["state"]), "assertionMethod must list the signing key");
}

#[then("the gateway DID log verifies as a did:webvh log")]
async fn gateway_did_log_verifies(world: &mut SurfaceWorld) {
    let versions = did_log_versions(world);
    let did = versions[0]["state"]["id"]
        .as_str()
        .expect("the first version names its DID")
        .to_string();
    let log = response_body(world)
        .as_str()
        .expect("the gateway DID log was fetched");
    let mut state = didwebvh_rs::DIDWebVHState::default();
    state
        .resolve_log(&did, log.trim_end(), None)
        .await
        .unwrap_or_else(|e| panic!("the gateway DID log must verify: {e}"));
}
