use cucumber::{given, then};
use serde_json::{Value, json};

use crate::bdd_support::actors::TargetActorKind;
use crate::bdd_support::config::single_surface_fixture::{ResponseAuthFixture, SEEDED_SURFACE_ID};
use crate::bdd_support::mock_server::MockTls;
use crate::steps::target_auth_save::draft;
use crate::steps::when::ensure_admin_session;
use crate::world::SurfaceWorld;

/// The stored surface's `target.response_auth` reads the managed agent's key from `header_name`
/// and accepts the keys of secret `secret_id`, which the appliance holds with `secret_value`.
#[given(
    expr = "the surface authenticates its Target's responses by the API key in secret {string} holding {string} in header {string}"
)]
fn surface_authenticates_target_responses(
    world: &mut SurfaceWorld,
    secret_id: String,
    secret_value: String,
    header_name: String,
) {
    world
        .surface_config
        .response_auth = Some(ResponseAuthFixture {
        secret_id,
        secret_value,
        header_name,
    });
}

#[given(expr = "the draft authenticates its Target's responses by the API key in secret {string} in header {string}")]
fn draft_authenticates_target_responses(
    world: &mut SurfaceWorld,
    secret_id: String,
    header_name: String,
) {
    draft(world)["target"]["response_auth"] = json!({"api_key": {"header_name": header_name, "secret_id": secret_id}});
}

#[given(expr = "the draft authenticates its Target's responses by the pinned certificate {string}")]
fn draft_authenticates_target_responses_by_pinned_certificate(
    world: &mut SurfaceWorld,
    certificate_id: String,
) {
    draft(world)["target"]["response_auth"] =
        json!({"mtls": {"server_trust": {"type": "pinned", "certificate_ids": [certificate_id]}}});
}

/// The certificate the scenario generated as `name`, generated now when it has not been.
fn certificate(
    world: &mut SurfaceWorld,
    name: &str,
) -> MockTls {
    world
        .tls_certificates
        .entry(name.to_string())
        .or_insert_with(MockTls::generate)
        .clone()
}

#[given(expr = "managed agent {string} serves https with certificate {string}")]
fn managed_agent_serves_https(
    world: &mut SurfaceWorld,
    agent_name: String,
    certificate_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    world.managed_agent_tls = Some(certificate(world, &certificate_name));
}

/// Stores the certificate generated as `name` as a client leaf certificate through the admin
/// API, with its private key when `with_key`, and returns its id.
async fn store_certificate(
    world: &mut SurfaceWorld,
    name: &str,
    with_key: bool,
) -> String {
    let generated = certificate(world, name);
    let mut body = json!({
        "name": name,
        "kind": "client_leaf",
        "certificate_pem": generated.certificate_pem,
        "active": true,
    });
    if with_key {
        body["private_key_pem"] = json!(generated.private_key_pem);
    }
    ensure_admin_session(world).await;
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_json(reqwest::Method::POST, "/api/v1/certificates", Some(&body))
        .await
        .unwrap_or_else(|error| panic!("storing certificate {name:?} through the admin API: {error}"));
    assert!(
        (200..300).contains(&response.status),
        "storing certificate {name:?} should succeed, got status {} body {}",
        response.status,
        response.body
    );
    let id = response.body["id"]
        .as_str()
        .unwrap_or_else(|| panic!("the stored certificate should have an id, got {}", response.body))
        .to_string();
    world
        .client_certificates
        .insert(name.to_string(), id.clone());
    id
}

/// Saves `response_auth` as the stored surface's `target.response_auth` through the admin API.
async fn save_response_auth(
    world: &mut SurfaceWorld,
    response_auth: Value,
) {
    ensure_admin_session(world).await;
    let surface_id = world
        .surface_under_test_id
        .clone()
        .unwrap_or_else(|| SEEDED_SURFACE_ID.to_string());
    let client = world
        .admin_client
        .as_ref()
        .expect("admin client must exist");
    let mut surface: Value = client
        .send_json::<(), _>(reqwest::Method::GET, &format!("/v1/surfaces/{surface_id}"), None)
        .await
        .unwrap_or_else(|error| {
            panic!("reading surface {surface_id} before setting its Response authentication: {error}")
        });
    surface["target"]["response_auth"] = response_auth;
    let response = client
        .update_surface_recorded(&surface_id, &surface)
        .await
        .unwrap_or_else(|error| panic!("setting the surface's Response authentication: {error}"));
    assert_eq!(
        response.status, 200,
        "setting the surface's Response authentication should succeed, got: {}",
        response.body
    );
}

#[given(expr = "the surface authenticates its Target's responses by the pinned certificate {string}")]
async fn surface_authenticates_by_pinned_certificate(
    world: &mut SurfaceWorld,
    certificate_name: String,
) {
    let pinned = store_certificate(world, &certificate_name, false).await;
    save_response_auth(world, json!({"mtls": {"server_trust": {"type": "pinned", "certificate_ids": [pinned]}}})).await;
}

#[given(
    expr = "the surface authenticates its Target's responses by the pinned certificate {string} and presents client certificate {string}"
)]
async fn surface_authenticates_by_pinned_certificate_presenting_client_certificate(
    world: &mut SurfaceWorld,
    certificate_name: String,
    client_certificate_name: String,
) {
    let pinned = store_certificate(world, &certificate_name, false).await;
    let client = store_certificate(world, &client_certificate_name, true).await;
    save_response_auth(
        world,
        json!({"mtls": {
            "server_trust": {"type": "pinned", "certificate_ids": [pinned]},
            "client_certificate_id": client
        }}),
    )
    .await;
}

#[then(expr = "managed agent {string} received client certificate {string}")]
fn managed_agent_received_client_certificate(
    world: &mut SurfaceWorld,
    agent_name: String,
    certificate_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    let expected = world
        .tls_certificates
        .get(&certificate_name)
        .unwrap_or_else(|| panic!("certificate {certificate_name:?} must have been generated before this step"))
        .der
        .clone();
    let received = world
        .infra
        .as_ref()
        .expect("scenario infrastructure")
        .mock
        .client_certificates();
    assert!(!received.is_empty(), "managed agent {agent_name:?} received no client certificate");
    assert!(
        received
            .iter()
            .all(|presented| *presented == expected),
        "managed agent {agent_name:?} received a client certificate other than {certificate_name:?}"
    );
}

#[then("no managed agent identity is issued")]
async fn no_managed_agent_identity_is_issued(world: &mut SurfaceWorld) {
    ensure_admin_session(world).await;
    let managed = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .managed_agent_identities()
        .await
        .unwrap_or_else(|error| panic!("reading the Identities dashboard: {error:#}"));
    assert!(managed.is_empty(), "expected no Managed Agent identity, observed: {managed:?}");
}
