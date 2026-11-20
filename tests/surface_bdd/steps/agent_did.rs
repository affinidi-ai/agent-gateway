use std::path::Path;

use cucumber::{given, then, when};
use serde_json::{Value, json};

use crate::steps::when::ensure_gateway_running;
use crate::world::SurfaceWorld;

/// How an agent DID log seeded before the gateway starts lists its signing key.
#[derive(Debug, Clone, Copy)]
pub(crate) enum AgentDidSeed {
    /// `#key-2` is published and listed under `assertionMethod` only.
    WithoutAuthentication,
    /// Only `#key-1` is published.
    WithoutSigningKey,
}

#[given("an agent DID published with its signing key under assertionMethod only")]
fn agent_did_without_authentication(world: &mut SurfaceWorld) {
    world.agent_did_seed = Some(AgentDidSeed::WithoutAuthentication);
}

#[given("an agent DID published without its signing key")]
fn agent_did_without_signing_key(world: &mut SurfaceWorld) {
    world.agent_did_seed = Some(AgentDidSeed::WithoutSigningKey);
}

/// Writes a local agent identity into the identity store at `identities`: its record, holding
/// the agent key, and its `did:webvh` birth log, signed and updatable by that key. Returns the
/// agent DID.
pub(crate) async fn seed_agent_did(
    identities: &Path,
    seed: AgentDidSeed,
) -> String {
    use didwebvh_rs::prelude::{CreateDIDConfig, Parameters, Secret, create_did};

    let id = uuid::Uuid::new_v4().to_string();
    let key = ssi::jwk::JWK::generate_ed25519().expect("generate the agent key");
    let key_json = serde_json::to_value(&key).expect("serialize the agent key");
    let multikey = Secret::from_jwk_value("did:key:seed#seed", &key_json)
        .expect("read the agent key")
        .get_public_keymultibase()
        .expect("encode the agent key as a Multikey");
    let placeholder = format!("did:webvh:{{SCID}}:localhost%3A1:surface:{id}");
    let key_1 = format!("{placeholder}#key-1");
    let key_2 = format!("{placeholder}#key-2");
    let mut methods = vec![json!({
        "id": key_1, "type": "JsonWebKey2020", "controller": placeholder, "publicKeyJwk": key.to_public(),
    })];
    let mut assertion = vec![json!(key_1)];
    if matches!(seed, AgentDidSeed::WithoutAuthentication) {
        methods.push(json!({
            "id": key_2, "type": "Multikey", "controller": placeholder, "publicKeyMultibase": multikey,
        }));
        assertion.push(json!(key_2));
    }
    let document = json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
        "id": placeholder,
        "verificationMethod": methods,
        "authentication": [key_1],
        "assertionMethod": assertion,
    });
    let update_key_id = format!("did:key:{multikey}#{multikey}");
    let created = create_did(
        CreateDIDConfig::builder()
            .address("http://localhost:1/".to_string())
            .authorization_key(Secret::from_jwk_value(&update_key_id, &key_json).expect("an update key"))
            .did_document(document)
            .parameters(Parameters {
                update_keys: Some(std::sync::Arc::new(vec![didwebvh_rs::Multibase::new(multikey.clone())])),
                ..Default::default()
            })
            .build()
            .expect("a did:webvh create config"),
    )
    .await
    .expect("create the agent DID");
    let did = created.did().to_string();

    std::fs::create_dir_all(identities.join(&id)).expect("create the agent DID folder");
    std::fs::write(
        identities
            .join(&id)
            .join("did.jsonl"),
        format!("{}\n", serde_json::to_string(created.log_entry()).expect("serialize the agent DID log entry")),
    )
    .expect("write the agent DID log");
    let record = json!({
        "did": did,
        "identity_hash": format!("seeded-{id}"),
        "created_at": chrono::Utc::now(),
        "identity_fields": {},
        "private_key": key_json,
    });
    std::fs::write(
        identities.join(format!("seeded-{id}.json")),
        serde_json::to_vec_pretty(&record).expect("serialize the agent identity record"),
    )
    .expect("write the agent identity record");
    did
}

#[when("the caller fetches the agent DID log")]
async fn agent_did_log_fetched(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    world.agent_did_log = Some(fetch_agent_did_log(world).await);
}

async fn fetch_agent_did_log(world: &SurfaceWorld) -> String {
    let did = world
        .seeded_agent_did
        .clone()
        .expect("an agent DID was seeded");
    let id = did
        .rsplit(':')
        .next()
        .expect("the agent DID has a last segment");
    let infra = world
        .infra
        .as_ref()
        .expect("scenario infra must exist");
    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/surface/{id}/did.jsonl", infra.gateway_port))
        .send()
        .await
        .expect("fetch the agent DID log");
    assert_eq!(response.status(), 200, "the agent DID log must be served");
    response
        .text()
        .await
        .expect("read the agent DID log")
}

/// The gateway repairs agent DIDs in the background after it starts, so the log is fetched again
/// until it has `count` versions or ten seconds pass.
#[then(expr = "within ten seconds the agent DID log has {int} version(s)")]
async fn agent_did_log_has_versions_within(
    world: &mut SurfaceWorld,
    count: usize,
) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if agent_did_log_versions(world).len() == count || std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        world.agent_did_log = Some(fetch_agent_did_log(world).await);
    }
    assert_eq!(agent_did_log_versions(world).len(), count);
}

fn agent_did_log_versions(world: &SurfaceWorld) -> Vec<Value> {
    world
        .agent_did_log
        .as_deref()
        .expect("the agent DID log was fetched")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("each agent DID log line is JSON"))
        .collect()
}

fn signing_key_of(document: &Value) -> String {
    format!(
        "{}#key-2",
        document["id"]
            .as_str()
            .expect("the DID document names its DID")
    )
}

fn publishes_signing_key(document: &Value) -> bool {
    let signing_key = signing_key_of(document);
    document["verificationMethod"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|method| method["id"] == signing_key.as_str() && method["type"] == "Multikey")
}

fn lists_signing_key_under(
    document: &Value,
    relationship: &str,
) -> bool {
    let signing_key = signing_key_of(document);
    document[relationship]
        .as_array()
        .into_iter()
        .flatten()
        .any(|id| *id == signing_key.as_str())
}

#[then("every version of the agent DID log describes the same agent DID")]
fn agent_did_log_keeps_its_did(world: &mut SurfaceWorld) {
    let did = world
        .seeded_agent_did
        .clone()
        .expect("an agent DID was seeded");
    for version in agent_did_log_versions(world) {
        assert_eq!(version["state"]["id"], did.as_str(), "every version must describe {did}");
    }
}

#[then("the first version of the agent DID log does not list the agent signing key under authentication")]
fn first_version_lacks_authentication(world: &mut SurfaceWorld) {
    let versions = agent_did_log_versions(world);
    assert!(!lists_signing_key_under(&versions[0]["state"], "authentication"));
}

#[then("the first version of the agent DID log does not publish the agent signing key")]
fn first_version_lacks_signing_key(world: &mut SurfaceWorld) {
    let versions = agent_did_log_versions(world);
    assert!(!publishes_signing_key(&versions[0]["state"]));
}

#[then("the latest version of the agent DID log lists the agent signing key under assertionMethod and authentication")]
fn latest_version_lists_signing_key(world: &mut SurfaceWorld) {
    let versions = agent_did_log_versions(world);
    let latest = &versions
        .last()
        .expect("the agent DID log has a version")["state"];
    assert!(publishes_signing_key(latest), "the signing key must be published as a Multikey: {latest}");
    for relationship in ["assertionMethod", "authentication"] {
        assert!(lists_signing_key_under(latest, relationship), "{relationship} must list the signing key: {latest}");
    }
}

#[then("the agent DID log verifies as a did:webvh log")]
async fn agent_did_log_verifies(world: &mut SurfaceWorld) {
    let did = world
        .seeded_agent_did
        .clone()
        .expect("an agent DID was seeded");
    let log = world
        .agent_did_log
        .as_deref()
        .expect("the agent DID log was fetched");
    let mut state = didwebvh_rs::DIDWebVHState::default();
    state
        .resolve_log(&did, log.trim_end(), None)
        .await
        .unwrap_or_else(|e| panic!("the agent DID log must verify: {e}"));
}
