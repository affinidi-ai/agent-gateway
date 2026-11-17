use cucumber::{given, then};

use crate::world::SurfaceWorld;

fn admin_body(world: &SurfaceWorld) -> &serde_json::Value {
    let response = world
        .admin_response
        .as_ref()
        .expect("an admin API response");
    assert_eq!(response.status, 200, "{}", response.body);
    &response.body
}

#[given("the deployment has trust agent contexts sign as a did:webvh on the trust agent's webvh server")]
async fn contexts_sign_as_did_webvh(world: &mut SurfaceWorld) {
    world
        .surface_config
        .contexts_sign_as_did_webvh = true;
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
