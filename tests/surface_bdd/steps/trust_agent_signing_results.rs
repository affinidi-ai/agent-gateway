use base64::Engine;
use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::bdd_support::signing_trust_agent::SigningTrustAgent;
use crate::steps::credential_save::send;
use crate::world::{RecordedResponse, SurfaceWorld};

const CONNECTION: &str = "Signing trust agent";
const AGENT_IDENTITY_CREDENTIAL_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity-credential/v1";
const AGENT_IDENTITY_BINDING_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity-binding/v1";

fn agent(world: &SurfaceWorld) -> &SigningTrustAgent {
    world
        .signing_trust_agent
        .as_ref()
        .expect("a trust agent that signs was connected")
}

fn signing_block(world: &SurfaceWorld) -> Value {
    let agent = agent(world);
    json!({
        "backend": "vta",
        "connection_id": world.trust_agent_connections[CONNECTION],
        "context_id": agent.context_id(),
        "key_id": agent.key_id(),
    })
}

fn decode_segment(segment: &str) -> Value {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .expect("a base64url JWT segment");
    serde_json::from_slice(&bytes).expect("a JSON JWT segment")
}

fn jwt_parts(jwt: &str) -> (Value, Value) {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "not a compact JWT: {jwt}");
    (decode_segment(parts[0]), decode_segment(parts[1]))
}

/// The first credential of a presentation, as a JSON document.
fn first_credential(presentation: &Value) -> Value {
    let presentation = match presentation {
        Value::String(text) => serde_json::from_str(text).unwrap_or_else(|_| {
            let (_, claims) = jwt_parts(text);
            claims
                .get("vp")
                .cloned()
                .unwrap_or(claims)
        }),
        other => other.clone(),
    };
    let credentials = presentation
        .get("verifiableCredential")
        .unwrap_or_else(|| panic!("the presentation carries no credential: {presentation}"));
    let credential = credentials
        .as_array()
        .and_then(|all| all.first())
        .unwrap_or(credentials)
        .clone();
    match credential {
        Value::String(text) => serde_json::from_str(&text).unwrap_or_else(|_| jwt_parts(&text).1),
        other => other,
    }
}

fn assert_issued_by_the_trust_agent_context(
    world: &SurfaceWorld,
    credential: &Value,
) {
    let agent = agent(world);
    let issuer = credential["issuer"]
        .as_str()
        .or_else(|| credential["issuer"]["id"].as_str());
    assert_eq!(issuer, Some(agent.context_did().as_str()), "{credential}");
    assert_eq!(credential["proof"]["verificationMethod"], json!(agent.verification_method()), "{credential}");
    assert!(agent.proved_document(credential), "the trust agent's key did not prove {credential}");
}

#[given(expr = "the operator has connected a trust agent that signs as its context {string} with key {string}")]
async fn operator_has_connected_a_signing_trust_agent(
    world: &mut SurfaceWorld,
    context_id: String,
    key_id: String,
) {
    crate::steps::when::ensure_gateway_running(world).await;
    let agent = SigningTrustAgent::start(&context_id, &key_id).await;
    let body = json!({
        "name": CONNECTION,
        "enabled": true,
        "transport": "https",
        "endpoint": agent.url,
        "vta_did": agent.context_did(),
        "default_context_id": context_id,
        "control_identity": "did_key",
    });
    let created = send(world, Method::POST, "/v1/vta/connections", Some(&body)).await;
    assert_eq!(created.status, 201, "creating the connection: {}", created.body);
    let id = created.body["id"]
        .as_str()
        .expect("an id")
        .to_string();
    let paired = send(world, Method::POST, &format!("/v1/vta/connections/{id}/pair"), None).await;
    assert_eq!(paired.status, 200, "pairing: {}", paired.body);
    let verified = send(world, Method::POST, &format!("/v1/vta/connections/{id}/verify"), None).await;
    assert_eq!(verified.status, 200, "verifying: {}", verified.body);
    assert_eq!(verified.body["pairing"]["state"], "connected", "{}", verified.body);
    world
        .trust_agent_connections
        .insert(CONNECTION.to_string(), id);
    world.signing_trust_agent = Some(agent);
}

#[given("the gateway signs through that trust agent by default")]
async fn gateway_signs_through_the_trust_agent_by_default(world: &mut SurfaceWorld) {
    let body = json!({ "default_signing": signing_block(world) });
    let response = send(world, Method::POST, "/v1/settings", Some(&body)).await;
    assert_eq!(response.status, 200, "setting the gateway-wide signing default: {}", response.body);
}

#[given("Gateway signing moves to the gateway's own key")]
async fn gateway_signing_moves_to_the_gateways_own_key(world: &mut SurfaceWorld) {
    let body = json!({ "default_signing": { "backend": "local" } });
    let response = send(world, Method::POST, "/v1/settings", Some(&body)).await;
    assert_eq!(response.status, 200, "moving Gateway signing to the gateway's own key: {}", response.body);
}

#[given("the operator revokes that trust agent's connection")]
async fn operator_revokes_that_trust_agents_connection(world: &mut SurfaceWorld) {
    let path = format!(
        "/v1/vta/connections/{}/revoke?acknowledge_signing_users=true&acknowledge_stranded_agents=true",
        world.trust_agent_connections[CONNECTION]
    );
    let response = send(world, Method::POST, &path, None).await;
    assert_eq!(response.status, 200, "revoking the trust agent's connection: {}", response.body);
}

/// Whether `/oauth2/jwks.json` publishes the trust agent's key now.
async fn publishes_the_trust_agents_key(world: &SurfaceWorld) -> bool {
    let port = world
        .infra
        .as_ref()
        .expect("the gateway is running")
        .gateway_port;
    let keys: Value = reqwest::get(format!("http://127.0.0.1:{port}/api/oauth2/jwks.json"))
        .await
        .expect("the key set request completes")
        .json()
        .await
        .expect("the key set is JSON");
    let agent = agent(world);
    keys["keys"]
        .as_array()
        .is_some_and(|keys| {
            keys.iter()
                .any(|key| key["kid"] == agent.key_id())
        })
}

#[then("the gateway still publishes the trust agent's key")]
async fn gateway_still_publishes_the_trust_agents_key(world: &mut SurfaceWorld) {
    assert!(publishes_the_trust_agents_key(world).await, "the earlier signer's key is published");
}

#[then("the gateway no longer publishes the trust agent's key")]
async fn gateway_no_longer_publishes_the_trust_agents_key(world: &mut SurfaceWorld) {
    assert!(!publishes_the_trust_agents_key(world).await, "a retired signer's key is not published");
}

#[given("the surface signs through that trust agent")]
async fn surface_signs_through_the_trust_agent(world: &mut SurfaceWorld) {
    let name = world
        .surface_config
        .surface_name
        .clone()
        .unwrap_or_default();
    let id = crate::steps::given::tracked_surface_id(world, &name);
    let path = format!("/v1/surfaces/{id}");
    let stored = send(world, Method::GET, &path, None).await;
    assert_eq!(stored.status, 200, "reading the surface: {}", stored.body);
    let mut surface = stored.body;
    surface["signing"] = signing_block(world);
    let saved = send(world, Method::PUT, &path, Some(&surface)).await;
    assert_eq!(saved.status, 200, "saving the surface signing through the trust agent: {}", saved.body);
}

#[given("the trust agent can no longer be reached")]
async fn trust_agent_can_no_longer_be_reached(world: &mut SurfaceWorld) {
    agent(world).stop();
}

#[when("a verifier reads the gateway's published token keys")]
async fn verifier_reads_published_token_keys(world: &mut SurfaceWorld) {
    let port = world
        .infra
        .as_ref()
        .expect("the gateway is running")
        .gateway_port;
    let response = reqwest::get(format!("http://127.0.0.1:{port}/api/oauth2/jwks.json"))
        .await
        .expect("the key set request completes");
    let status = response.status().as_u16();
    let body = response
        .json::<Value>()
        .await
        .unwrap_or(Value::Null);
    world.caller_response = Some(RecordedResponse {
        status,
        headers: Default::default(),
        body,
    });
}

fn issued_token(world: &SurfaceWorld) -> String {
    let body = &world
        .caller_response
        .as_ref()
        .expect("a token was asked for")
        .body;
    body["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("no token was issued: {body}"))
        .to_string()
}

#[then("the issued token is signed by the trust agent's key")]
async fn issued_token_is_signed_by_the_trust_agent(world: &mut SurfaceWorld) {
    let token = issued_token(world);
    let (header, _) = jwt_parts(&token);
    let agent = agent(world);
    assert_eq!(header["alg"], "EdDSA", "{header}");
    assert_eq!(header["kid"], json!(agent.key_id()), "{header}");
    assert!(agent.signed_jws(&token), "the trust agent's key did not sign {token}");
}

#[then("the issued token names the trust agent context's DID as its issuer")]
async fn issued_token_names_the_context_did(world: &mut SurfaceWorld) {
    let (_, claims) = jwt_parts(&issued_token(world));
    assert_eq!(claims["iss"], json!(agent(world).context_did()), "{claims}");
}

#[then("the published token keys include the trust agent's key")]
async fn published_keys_include_the_trust_agent_key(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("the key set was read");
    assert_eq!(response.status, 200, "{}", response.body);
    let agent = agent(world);
    let keys = response.body["keys"]
        .as_array()
        .unwrap_or_else(|| panic!("no keys in {}", response.body));
    assert!(
        keys.iter()
            .any(|key| key["kid"] == agent.key_id() && key["x"] == agent.public_jwk_x() && key["crv"] == "Ed25519"),
        "the trust agent's key is not published: {}",
        response.body
    );
}

#[then(expr = "MCP server {string} received a presentation whose credential the trust agent context issued")]
async fn mcp_server_received_credential_issued_by_the_context(
    world: &mut SurfaceWorld,
    server_name: String,
) {
    let request = crate::steps::then::get_mcp_request_for_actor(world, &server_name);
    let body = request.json_body();
    let meta = body
        .pointer("/params/_meta")
        .or_else(|| body.get("_meta"))
        .unwrap_or_else(|| panic!("the forwarded request carries no _meta: {body}"));
    let binding = meta
        .get(AGENT_IDENTITY_BINDING_URI)
        .or_else(|| meta.get("io.affinidi.fabric/agent-identity-binding"))
        .unwrap_or_else(|| panic!("the forwarded request carries no identity binding: {meta}"));
    let credential = first_credential(&binding["verifiablePresentation"]);
    assert_issued_by_the_trust_agent_context(world, &credential);
}

#[then("the agent card carries a presentation whose credential the trust agent context issued")]
async fn agent_card_carries_credential_issued_by_the_context(world: &mut SurfaceWorld) {
    let body = crate::steps::then::get_response_body_value(world).clone();
    let extension = body["capabilities"]["extensions"]
        .as_array()
        .and_then(|extensions| {
            extensions
                .iter()
                .find(|ext| ext["uri"] == AGENT_IDENTITY_CREDENTIAL_URI)
        })
        .unwrap_or_else(|| panic!("the agent card carries no credential extension: {body}"));
    let credential = first_credential(&extension["params"]["verifiablePresentation"]);
    assert_issued_by_the_trust_agent_context(world, &credential);
}

#[then("the MCP response carries a presentation whose credential the trust agent context issued")]
async fn mcp_response_carries_credential_issued_by_the_context(world: &mut SurfaceWorld) {
    let body = world
        .caller_response
        .as_ref()
        .expect("the caller got a response")
        .body
        .clone();
    let extension = body
        .pointer("/result/_meta")
        .and_then(|meta| meta.get(AGENT_IDENTITY_CREDENTIAL_URI))
        .unwrap_or_else(|| panic!("the MCP response carries no credential extension: {body}"));
    let credential = first_credential(&extension["verifiablePresentation"]);
    assert_issued_by_the_trust_agent_context(world, &credential);
}
