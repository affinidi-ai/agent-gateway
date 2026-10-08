use base64::Engine as _;
use cucumber::{given, then};
use serde_json::Value;

use crate::bdd_support::actors::TargetActorKind;
use crate::bdd_support::mock_server::{MockResponse, ReceivedRequest};
use crate::world::SurfaceWorld;

const IDENTITY_PROOF_URIS: [&str; 2] = [
    "https://fabric.affinidi.io/extensions/agent-identity-binding/v1",
    "https://fabric.affinidi.io/extensions/agent-identity-credential/v1",
];

fn forwarded_request<'a>(
    world: &'a SurfaceWorld,
    actor_name: &str,
    kind: TargetActorKind,
) -> &'a ReceivedRequest {
    world
        .actors
        .expect_target_kind(actor_name, kind);
    let requests = world
        .collaborator_target(
            world
                .actors
                .target_collaborator_key(actor_name),
        )
        .observations
        .as_ref()
        .unwrap_or_else(|| panic!("{kind:?} '{actor_name}' observations must be recorded"))
        .requests
        .as_slice();
    assert_eq!(requests.len(), 1, "expected {kind:?} '{actor_name}' to receive exactly one request, got {requests:?}");
    &requests[0]
}

#[given(expr = "managed agent {string} serves an Agent Card named {string}")]
async fn managed_agent_serves_named_agent_card(
    world: &mut SurfaceWorld,
    agent_name: String,
    card_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    crate::steps::when::ensure_gateway_running(world).await;
    world
        .mock_for_target(&agent_name)
        .set_response(MockResponse::json(serde_json::json!({ "name": card_name })))
        .await;
}

fn decode_json_or_jwt(value: &Value) -> Value {
    let Value::String(text) = value else {
        return value.clone();
    };
    if let Ok(json) = serde_json::from_str::<Value>(text) {
        return json;
    }
    let payload = text
        .split('.')
        .nth(1)
        .unwrap_or_else(|| panic!("credential string should be JSON or a JWT, got: {text}"));
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("JWT payload should be base64url encoded");
    serde_json::from_slice(&bytes).expect("JWT payload should be JSON")
}

fn identity_credential_subject(
    request: &ReceivedRequest,
    context: &str,
) -> Value {
    let body = request.json_body();
    let proof = IDENTITY_PROOF_URIS
        .iter()
        .find_map(|uri| body.pointer(&format!("/params/message/metadata/{}", uri.replace('/', "~1"))))
        .unwrap_or_else(|| panic!("{context} forwarded A2A request should carry identity proof metadata, got: {body}"));
    let decoded = decode_json_or_jwt(&proof["verifiablePresentation"]);
    let presentation = decoded
        .get("vp")
        .unwrap_or(&decoded);
    let credentials = presentation
        .get("verifiableCredential")
        .unwrap_or_else(|| panic!("{context} VP should contain a verifiableCredential, got: {decoded}"));
    let credential = credentials
        .as_array()
        .and_then(|all| all.first())
        .unwrap_or(credentials);
    let credential = decode_json_or_jwt(credential);
    credential
        .get("credentialSubject")
        .cloned()
        .unwrap_or_else(|| panic!("{context} credential should contain credentialSubject, got: {credential}"))
}

#[then(expr = "external agent {string} received the forwarded request with a VP naming the managed agent {string}")]
fn external_agent_received_vp_naming_managed_agent(
    world: &mut SurfaceWorld,
    agent_name: String,
    expected_name: String,
) {
    let context = format!("external agent '{agent_name}'");
    let request = forwarded_request(world, &agent_name, TargetActorKind::ExternalAgent);
    let subject = identity_credential_subject(request, &context);
    assert_eq!(
        subject.get("name"),
        Some(&Value::String(expected_name.clone())),
        "{context} VP credential should name the managed agent {expected_name:?}, got credentialSubject: {subject}"
    );
}

#[then(expr = "managed agent {string} received the forwarded request with a VP that names no agent")]
fn managed_agent_received_vp_naming_no_agent(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    let context = format!("managed agent '{agent_name}'");
    let request = forwarded_request(world, &agent_name, TargetActorKind::ManagedAgent);
    let subject = identity_credential_subject(request, &context);
    assert_eq!(
        subject.get("name"),
        None,
        "{context} VP credential should carry no display name, got credentialSubject: {subject}"
    );
}
