use cucumber::{given, then, when};
use serde_json::json;

use crate::steps::credential_save::{create_secret_with_value, save_surface, stored_surface};
use crate::steps::given::CALLER_KEY_SECRET_VALUE;
use crate::steps::target_auth_save::draft;
use crate::world::SurfaceWorld;

#[given(expr = "the appliance holds a 32-byte secret {string}")]
async fn appliance_holds_a_32_byte_secret(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    create_secret_with_value(world, &secret_id, None, CALLER_KEY_SECRET_VALUE).await;
}

#[given(expr = "the draft derives caller keys from secret {string}")]
fn draft_derives_caller_keys(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    draft(world)["caller_key"] = json!({ "secret_id": secret_id });
}

#[given(expr = "the draft derives caller keys in header {string} from secret {string}")]
fn draft_derives_caller_keys_in_header(
    world: &mut SurfaceWorld,
    header: String,
    secret_id: String,
) {
    draft(world)["caller_key"] = json!({ "secret_id": secret_id, "header": header });
}

/// A PUT of the stored surface with no `caller_key` field, as the Surface Builder sends.
#[when("the operator saves the surface without its caller key")]
async fn operator_saves_surface_without_caller_key(world: &mut SurfaceWorld) {
    let mut surface = stored_surface(world).await;
    assert!(surface["caller_key"].is_object(), "the stored surface has a caller key: {surface}");
    surface
        .as_object_mut()
        .expect("the stored surface is an object")
        .remove("caller_key");
    save_surface(world, &surface).await;
}

#[then(expr = "the stored surface derives caller keys in header {string} from secret {string}")]
async fn stored_surface_derives_caller_keys(
    world: &mut SurfaceWorld,
    header: String,
    secret_id: String,
) {
    let surface = stored_surface(world).await;
    assert_eq!(surface["caller_key"]["secret_id"], json!(secret_id), "the stored surface: {surface}");
    assert_eq!(surface["caller_key"]["header"], json!(header), "the stored surface: {surface}");
}
