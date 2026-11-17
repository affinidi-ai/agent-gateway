use cucumber::{given, then, when};

use crate::bdd_support::admin_client::RecordedResponse;
use crate::bdd_support::http::collect_headers;
use crate::steps::when::ensure_gateway_running;
use crate::world::SurfaceWorld;

/// The hosting token of the context whose `did:webvh` log the gateway published.
const PUBLISHED_TOKEN: &str = "ctx-0123456789abcdef0123";
/// A token of the same shape that names no published log.
const UNPUBLISHED_TOKEN: &str = "ctx-fedcba9876543210fedc";
const PUBLISHED_LOG: &str = r#"{"versionId":"1-QmBddContextDid","parameters":{"method":"did:webvh:1.0"}}"#;

fn admin_body(world: &SurfaceWorld) -> &serde_json::Value {
    let response = world
        .admin_response
        .as_ref()
        .expect("an admin API response");
    assert_eq!(response.status, 200, "{}", response.body);
    &response.body
}

#[given("the deployment has trust agent contexts sign as a did:webvh on the trust agent's webvh server")]
async fn contexts_sign_as_did_webvh_on_the_vta_server(world: &mut SurfaceWorld) {
    world
        .surface_config
        .context_did_webvh_hosting = Some("vta_server");
}

#[given("the deployment has trust agent contexts sign as a did:webvh this gateway hosts")]
async fn contexts_sign_as_did_webvh_hosted_here(world: &mut SurfaceWorld) {
    world
        .surface_config
        .context_did_webvh_hosting = Some("gateway");
}

#[given("the gateway has published the log of a context's did:webvh")]
async fn gateway_published_a_context_log(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let dir = world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        ._temp_dir
        .path()
        .join("_storage/vc_keys/vta-issuer")
        .join(PUBLISHED_TOKEN);
    std::fs::create_dir_all(&dir).expect("create the hosted log directory");
    std::fs::write(dir.join("did.jsonl"), format!("{PUBLISHED_LOG}\n")).expect("write the hosted log");
}

async fn fetch_context_did_log(
    world: &mut SurfaceWorld,
    token: &str,
) {
    ensure_gateway_running(world).await;
    let port = world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        .gateway_port;
    let path = format!("/vta-issuer/{token}/did.jsonl");
    let response = reqwest::get(format!("http://127.0.0.1:{port}{path}"))
        .await
        .unwrap_or_else(|error| panic!("GET {path}: {error}"));
    let status = response.status().as_u16();
    let headers = collect_headers(response.headers());
    let body = response
        .text()
        .await
        .unwrap_or_else(|error| panic!("read {path}: {error}"));
    world.caller_response = Some(RecordedResponse {
        status,
        headers,
        body: serde_json::Value::String(body),
    });
}

#[when("a verifier resolves that did:webvh")]
async fn verifier_resolves_the_published_did(world: &mut SurfaceWorld) {
    fetch_context_did_log(world, PUBLISHED_TOKEN).await;
}

#[when("a verifier resolves a context did:webvh this gateway never published")]
async fn verifier_resolves_an_unpublished_did(world: &mut SurfaceWorld) {
    fetch_context_did_log(world, UNPUBLISHED_TOKEN).await;
}

#[then("the verifier receives the published did:webvh log")]
async fn verifier_receives_the_log(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("a response to the verifier");
    assert_eq!(response.status, 200, "{}", response.body);
    let content_type = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.as_str());
    assert_eq!(content_type, Some("text/jsonl"));
    assert_eq!(
        response
            .body
            .as_str()
            .map(str::trim_end),
        Some(PUBLISHED_LOG)
    );
}

#[then("the verifier is told the DID log is not found")]
async fn verifier_is_told_not_found(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("a response to the verifier");
    assert_eq!(response.status, 404, "{}", response.body);
}

#[then(expr = "the trust agent status says new contexts sign as {string}")]
async fn status_reports_method(
    world: &mut SurfaceWorld,
    method: String,
) {
    assert_eq!(admin_body(world)["context_did_method"], method.as_str());
}

#[then(expr = "the trust agent status says new contexts sign as {string} hosted on {string}")]
async fn status_reports_method_and_hosting(
    world: &mut SurfaceWorld,
    method: String,
    hosting: String,
) {
    let body = admin_body(world);
    assert_eq!(body["context_did_method"], method.as_str());
    assert_eq!(body["context_did_hosting"], hosting.as_str());
}

#[then(expr = "the key inventory says new contexts sign as {string}")]
async fn inventory_reports_method(
    world: &mut SurfaceWorld,
    method: String,
) {
    assert_eq!(admin_body(world)["context_did_method"], method.as_str());
}
