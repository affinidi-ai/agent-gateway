use cucumber::{given, when};
use serde_json::{Value, json};

use crate::bdd_support::presentation_signer::PresentationSigner;
use crate::steps::when::send_json_request_and_record;
use crate::world::{RequestPolicyFixture, SurfaceWorld};

const AGENT_IDENTITY_CREDENTIAL_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity-credential/v1";

fn presentation_signer(world: &SurfaceWorld) -> &PresentationSigner {
    world
        .presentation_signer
        .as_ref()
        .expect("the caller must have published its DID")
}

fn message_with_presentation(
    holder: &str,
    presentation: &Value,
) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "bdd-presentation",
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "messageId": format!("bdd-message-{}", uuid::Uuid::new_v4()),
                "parts": [{ "kind": "text", "text": "hello" }],
                "extensions": [AGENT_IDENTITY_CREDENTIAL_URI],
                "metadata": {
                    AGENT_IDENTITY_CREDENTIAL_URI: {
                        "did": holder,
                        "verifiablePresentation": presentation.to_string(),
                    }
                }
            }
        }
    })
}

/// The receiver a caller names in its presentation: the origin the gateway's inbound listener lists
/// in `external_urls`. Starts the gateway, so its port is known.
async fn access_point_origin(world: &mut SurfaceWorld) -> String {
    crate::steps::when::ensure_gateway_running(world).await;
    let port = world
        .infra
        .as_ref()
        .expect("the gateway is running")
        .gateway_port;
    format!("http://localhost:{port}")
}

async fn send_presentation(
    world: &mut SurfaceWorld,
    presentation: Value,
    headers: Vec<(String, String)>,
) {
    let holder = presentation_signer(world)
        .did()
        .to_string();
    send_json_request_and_record(world, message_with_presentation(&holder, &presentation), headers).await;
}

#[given("the surface has a request policy that requires a verified caller identity")]
fn surface_requires_verified_caller_identity(world: &mut SurfaceWorld) {
    let rego = r#"package surface.policy

default allow := false

allow if input.extension_identity.verified == true

deny_reason := "the request carries no verified caller identity" if not allow
"#;
    world
        .surface_config
        .request_policy = Some(RequestPolicyFixture::new(
        format!("bdd-verified-caller-policy-{}", uuid::Uuid::new_v4()),
        "BDD verified caller identity policy",
        rego.to_string(),
    ));
}

#[given("the caller's DID document lists its key for authentication only")]
async fn caller_lists_key_for_authentication_only(world: &mut SurfaceWorld) {
    world.presentation_signer = Some(PresentationSigner::publish(&["authentication"]).await);
}

#[given("the caller has since listed its key for assertions in its DID document")]
async fn caller_lists_key_for_assertions(world: &mut SurfaceWorld) {
    presentation_signer(world)
        .republish(&["authentication", "assertionMethod"])
        .await;
}

#[given("the gateway has accepted a presentation from the caller of a credential from another issuer")]
async fn gateway_accepted_presentation_of_credential_from_another_issuer(world: &mut SurfaceWorld) {
    let receiver = access_point_origin(world).await;
    let presentation = presentation_signer(world)
        .present_credential_from_another_issuer(&receiver)
        .await;
    send_presentation(world, presentation, vec![]).await;
    let status = world
        .caller_response
        .as_ref()
        .map(|response| response.status);
    assert_eq!(status, Some(200), "the gateway must accept the caller's first presentation");
    world
        .infra
        .as_ref()
        .expect("the gateway runs after the first request")
        .mock
        .clear_requests()
        .await;
}

#[when("the caller sends a request with a presentation of a credential it issued itself")]
async fn caller_sends_presentation_of_own_credential(world: &mut SurfaceWorld) {
    let receiver = access_point_origin(world).await;
    let presentation = presentation_signer(world)
        .present_own_credential(&receiver)
        .await;
    send_presentation(world, presentation, vec![]).await;
}

#[given("the caller's DID document lists its key for assertions")]
async fn caller_lists_key_for_assertions_from_the_start(world: &mut SurfaceWorld) {
    world.presentation_signer = Some(PresentationSigner::publish(&["authentication", "assertionMethod"]).await);
}

#[when(
    "the caller sends a request to the surface with a valid API key and a presentation of a credential it issued itself"
)]
async fn caller_with_api_key_sends_presentation_of_own_credential(world: &mut SurfaceWorld) {
    let receiver = access_point_origin(world).await;
    let header = crate::steps::when::build_valid_api_key_source_auth_header(world);
    let presentation = presentation_signer(world)
        .present_own_credential(&receiver)
        .await;
    send_presentation(world, presentation, vec![header]).await;
}
