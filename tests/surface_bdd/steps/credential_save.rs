use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::bdd_support::admin_client::RecordedResponse;
use crate::bdd_support::config::single_surface_fixture::TargetAuthClientAuthentication;
use crate::steps::when::{build_primary_target_surface_payload, ensure_admin_session};
use crate::world::SurfaceWorld;

pub(crate) async fn send(
    world: &mut SurfaceWorld,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> RecordedResponse {
    ensure_admin_session(world).await;
    world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_json(method, path, body)
        .await
        .unwrap_or_else(|error| panic!("{path} through admin API: {error}"))
}

pub(crate) const SECRET_VALUE: &str = "bdd-secret-value";

pub(crate) async fn create_secret(
    world: &mut SurfaceWorld,
    secret_id: &str,
    tenant: Option<&str>,
) {
    create_secret_with_value(world, secret_id, tenant, SECRET_VALUE).await;
}

async fn create_secret_with_value(
    world: &mut SurfaceWorld,
    secret_id: &str,
    tenant: Option<&str>,
    value: &str,
) {
    let body = json!({"name": secret_id, "secret_id": secret_id, "value": value, "tenant_id": tenant});
    let response = send(world, Method::POST, "/v1/secrets/new", Some(&body)).await;
    assert_eq!(response.status, 201, "creating a secret for tenant {tenant:?}: {}", response.body);
}

fn client_credentials_provider_body(
    provider_id: &str,
    token_endpoint: &str,
    tenant: Option<&str>,
    client_secrets: (&str, &str),
) -> Value {
    json!({
        "name": provider_id, "provider_id": provider_id, "provider_type": "oauth2_client_credentials",
        "token_endpoint": token_endpoint,
        "client_id_secret_ref": client_secrets.0, "client_secret_secret_ref": client_secrets.1,
        "tenant_id": tenant
    })
}

pub(crate) async fn create_provider(
    world: &mut SurfaceWorld,
    provider_id: &str,
    token_endpoint: &str,
    tenant: Option<&str>,
    client_secrets: (&str, &str),
) {
    let body = client_credentials_provider_body(provider_id, token_endpoint, tenant, client_secrets);
    let response = send(world, Method::POST, "/v1/credential-providers", Some(&body)).await;
    world.admin_response = Some(response);
}

async fn create_authorization_code_provider(
    world: &mut SurfaceWorld,
    provider_id: &str,
    tenant: Option<&str>,
    client_secrets: (&str, &str),
    callback_url: Option<&str>,
) -> RecordedResponse {
    let body = json!({
        "name": provider_id, "provider_id": provider_id, "provider_type": "oauth2_authorization_code",
        "authorization_endpoint": "https://192.0.2.1/authorize", "token_endpoint": "https://192.0.2.1/token",
        "client_id_secret_ref": client_secrets.0, "client_secret_secret_ref": client_secrets.1,
        "tenant_id": tenant, "callback_url": callback_url
    });
    send(world, Method::POST, "/v1/credential-providers", Some(&body)).await
}

#[given(
    expr = "the operator has created the authorization code provider {string} for tenant {string} using secrets {string} and {string}"
)]
async fn operator_has_created_tenant_authorization_code_provider(
    world: &mut SurfaceWorld,
    provider_id: String,
    tenant: String,
    client_id_secret: String,
    client_secret_secret: String,
) {
    let response = create_authorization_code_provider(
        world,
        &provider_id,
        Some(&tenant),
        (&client_id_secret, &client_secret_secret),
        None,
    )
    .await;
    assert_eq!(response.status, 201, "creating provider {provider_id} for {tenant}: {}", response.body);
}

#[when(
    expr = "the operator creates the authorization code provider {string} for tenant {string} using secrets {string} and {string}"
)]
async fn operator_creates_tenant_authorization_code_provider(
    world: &mut SurfaceWorld,
    provider_id: String,
    tenant: String,
    client_id_secret: String,
    client_secret_secret: String,
) {
    let response = create_authorization_code_provider(
        world,
        &provider_id,
        Some(&tenant),
        (&client_id_secret, &client_secret_secret),
        None,
    )
    .await;
    world.admin_response = Some(response);
}

#[when(
    expr = "the operator creates the authorization code provider {string} with callback URL {string} using secrets {string} and {string}"
)]
async fn operator_creates_authorization_code_provider_with_callback_url(
    world: &mut SurfaceWorld,
    provider_id: String,
    callback_url: String,
    client_id_secret: String,
    client_secret_secret: String,
) {
    let response = create_authorization_code_provider(
        world,
        &provider_id,
        None,
        (&client_id_secret, &client_secret_secret),
        Some(&callback_url),
    )
    .await;
    world.admin_response = Some(response);
}

#[when("the operator reads the surface routing settings")]
async fn operator_reads_surface_routing_settings(world: &mut SurfaceWorld) {
    let response = send(world, Method::GET, "/v1/config/surface-routing", None).await;
    world.admin_response = Some(response);
}

#[then("the surface routing settings name the gateway's own https address as its base URL")]
fn surface_routing_settings_name_gateway_base_url(world: &mut SurfaceWorld) {
    let base_url = format!(
        "https://localhost:{}",
        world
            .infra
            .as_ref()
            .expect("the gateway is running")
            .gateway_port
    );
    let response = world
        .admin_response
        .as_ref()
        .expect("an admin API response");
    assert_eq!(response.body["gateway_base_url"], base_url, "surface routing settings: {}", response.body);
}

#[then(expr = "both credential providers {string} have a callback path ending in the id the gateway gave each")]
async fn each_provider_has_a_callback_path_of_its_own(
    world: &mut SurfaceWorld,
    provider_id: String,
) {
    let response = send(world, Method::GET, "/v1/credential-providers", None).await;
    assert_eq!(response.status, 200, "listing credential providers: {}", response.body);
    let ids: Vec<String> = response
        .body
        .as_array()
        .expect("the provider list is an array")
        .iter()
        .filter(|provider| provider["provider_id"] == provider_id.as_str())
        .filter_map(|provider| {
            provider["id"]
                .as_str()
                .map(str::to_string)
        })
        .collect();
    assert_eq!(ids.len(), 2, "expected two providers {provider_id}, got {ids:?}");
    for id in &ids {
        let stored = send(world, Method::GET, &format!("/v1/credential-providers/{id}"), None).await;
        assert_eq!(stored.status, 200, "reading provider {id}: {}", stored.body);
        let path = stored.body["callback_path"]
            .as_str()
            .unwrap_or_default();
        assert_eq!(
            path,
            format!("/v1/identity/oauth/callback/{id}"),
            "provider {id} should have the consent route the gateway serves, ending in its id"
        );
    }
}

fn jwt_bearer_provider_body(
    provider_id: &str,
    signing_key_secret: &str,
    subject: Option<&str>,
) -> Value {
    let mut body = json!({
        "name": provider_id, "provider_id": provider_id, "provider_type": "oauth2_jwt_bearer",
        "token_endpoint": "https://192.0.2.1/token",
        "jwt_issuer": "bdd-issuer@example.com",
        "jwt_signing_key_secret_ref": signing_key_secret,
        "jwt_key_id": "bdd-key-id",
    });
    if let Some(subject) = subject {
        body["jwt_subject"] = json!(subject);
    }
    body
}

async fn create_jwt_bearer_provider(
    world: &mut SurfaceWorld,
    provider_id: &str,
    signing_key_secret: &str,
    subject: Option<&str>,
) {
    let body = jwt_bearer_provider_body(provider_id, signing_key_secret, subject);
    let response = send(world, Method::POST, "/v1/credential-providers", Some(&body)).await;
    world.admin_response = Some(response);
}

struct ClientAuthenticationFields<'a> {
    authentication: &'a str,
    client_id_secret: &'a str,
    client_secret: Option<&'a str>,
}

async fn create_jwt_bearer_provider_authenticating_its_client(
    world: &mut SurfaceWorld,
    provider_id: &str,
    signing_key_secret: &str,
    subject: &str,
    client: ClientAuthenticationFields<'_>,
) {
    let mut body = jwt_bearer_provider_body(provider_id, signing_key_secret, Some(subject));
    body["client_authentication"] =
        json!(TargetAuthClientAuthentication::from_wording(client.authentication).api_value());
    body["client_id_secret_ref"] = json!(client.client_id_secret);
    if let Some(client_secret) = client.client_secret {
        body["client_secret_secret_ref"] = json!(client_secret);
    }
    let response = send(world, Method::POST, "/v1/credential-providers", Some(&body)).await;
    world.admin_response = Some(response);
}

async fn validate_jwt_bearer_provider(
    world: &mut SurfaceWorld,
    signing_key_secret: &str,
    subject: Option<&str>,
) {
    let mut body = json!({
        "provider_type": "oauth2_jwt_bearer",
        "token_endpoint": "https://192.0.2.1/token",
        "jwt_issuer": "bdd-issuer@example.com",
        "jwt_signing_key_secret_ref": signing_key_secret,
        "jwt_key_id": "bdd-key-id",
    });
    if let Some(subject) = subject {
        body["jwt_subject"] = json!(subject);
    }
    let response = send(world, Method::POST, "/v1/credential-providers/validate", Some(&body)).await;
    world.admin_response = Some(response);
}

#[when(expr = "the operator validates a JWT Bearer provider using the secret {string} without a subject")]
async fn operator_validates_jwt_bearer_without_subject(
    world: &mut SurfaceWorld,
    secret: String,
) {
    validate_jwt_bearer_provider(world, &secret, None).await;
}

#[when(expr = "the operator validates a JWT Bearer provider using the secret {string} with subject {string}")]
async fn operator_validates_jwt_bearer_with_subject(
    world: &mut SurfaceWorld,
    secret: String,
    subject: String,
) {
    validate_jwt_bearer_provider(world, &secret, Some(&subject)).await;
}

fn static_secret(secret_id: &str) -> Value {
    json!({"method": {"static_secret": {"secret_id": secret_id, "header_name": "Authorization"}}})
}

async fn create_surface_with_secret(
    world: &mut SurfaceWorld,
    route: &str,
    tenant: Option<&str>,
    secret_id: &str,
) {
    let mut payload = build_primary_target_surface_payload(world, route).await;
    payload["name"] = json!(route.trim_start_matches('/'));
    payload["status"] = json!("disabled");
    payload["tenant_id"] = json!(tenant);
    payload["target"]["auth"] = static_secret(secret_id);
    // A Target credential is saved only for an https Target of a surface that checks its
    // callers; these scenarios send no traffic, so an unreachable https address will do.
    payload["target"]["endpoint"] = json!("https://127.0.0.1:9/");
    payload["access_point"]["caller_authentication"] = json!({"methods": [{
        "type": "api_key", "secret_id": secret_id,
        "extraction": {"source": "http_header", "field": "X-Caller-Key"}
    }]});
    let response = send(world, Method::POST, "/v1/surfaces", Some(&payload)).await;
    assert_eq!(response.status, 201, "creating surface {route}: {}", response.body);
    world.surface_under_test_id = response.body["surface_id"]
        .as_str()
        .map(str::to_string);
    assert!(
        world
            .surface_under_test_id
            .is_some(),
        "the created surface has an id: {}",
        response.body
    );
}

const SEEDED_SURFACE_ID: &str = "bdd-surface";

pub(crate) fn surface_id(world: &SurfaceWorld) -> String {
    world
        .surface_under_test_id
        .clone()
        .or_else(|| {
            world
                .surface_config
                .seed_surface
                .then(|| SEEDED_SURFACE_ID.to_string())
        })
        .expect("the surface under test must exist")
}

pub(crate) async fn stored_surface(world: &mut SurfaceWorld) -> Value {
    let path = format!("/v1/surfaces/{}", surface_id(world));
    let response = send(world, Method::GET, &path, None).await;
    assert_eq!(response.status, 200, "reading the stored surface: {}", response.body);
    response.body
}

pub(crate) async fn save_surface(
    world: &mut SurfaceWorld,
    surface: &Value,
) {
    let path = format!("/v1/surfaces/{}", surface_id(world));
    let response = send(world, Method::PUT, &path, Some(surface)).await;
    world.admin_response = Some(response);
}

async fn provider_ids(world: &mut SurfaceWorld) -> Vec<String> {
    let response = send(world, Method::GET, "/v1/credential-providers", None).await;
    assert_eq!(response.status, 200, "listing credential providers: {}", response.body);
    response
        .body
        .as_array()
        .expect("the provider list is an array")
        .iter()
        .filter_map(|provider| {
            provider["provider_id"]
                .as_str()
                .map(str::to_string)
        })
        .collect()
}

#[given(expr = "the appliance holds the secret {string}")]
async fn appliance_holds_secret(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    create_secret(world, &secret_id, None).await;
}

#[given(expr = "the appliance holds the signing key {string}")]
async fn appliance_holds_signing_key(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    let key = crate::bdd_support::config::target_auth::target_auth_signing_key();
    create_secret_with_value(world, &secret_id, None, &key.private_pem).await;
}

#[given(expr = "tenant {string} holds the secret {string}")]
async fn tenant_holds_secret(
    world: &mut SurfaceWorld,
    tenant: String,
    secret_id: String,
) {
    create_secret(world, &secret_id, Some(&tenant)).await;
}

#[given(
    expr = "the operator has created the surface for route {string} owned by tenant {string} authenticating its target with secret {string}"
)]
async fn operator_created_tenant_surface(
    world: &mut SurfaceWorld,
    route: String,
    tenant: String,
    secret_id: String,
) {
    create_surface_with_secret(world, &route, Some(&tenant), &secret_id).await;
}

#[given(
    expr = "the operator has created the appliance-wide surface for route {string} authenticating its target with secret {string}"
)]
async fn operator_created_appliance_surface(
    world: &mut SurfaceWorld,
    route: String,
    secret_id: String,
) {
    create_surface_with_secret(world, &route, None, &secret_id).await;
}

#[when(
    expr = "the operator creates the credential provider {string} with token endpoint {string} using secrets {string} and {string}, authenticating its client with {string}"
)]
async fn operator_creates_provider_authenticating_its_client(
    world: &mut SurfaceWorld,
    provider_id: String,
    token_endpoint: String,
    client_id_secret: String,
    client_secret_secret: String,
    authentication: String,
) {
    let mut body = client_credentials_provider_body(
        &provider_id,
        &token_endpoint,
        None,
        (&client_id_secret, &client_secret_secret),
    );
    body["client_authentication"] = json!(TargetAuthClientAuthentication::from_wording(&authentication).api_value());
    let response = send(world, Method::POST, "/v1/credential-providers", Some(&body)).await;
    world.admin_response = Some(response);
}

#[when(
    expr = "the operator creates the credential provider {string} with token endpoint {string} using secrets {string} and {string}"
)]
async fn operator_creates_appliance_provider(
    world: &mut SurfaceWorld,
    provider_id: String,
    token_endpoint: String,
    client_id_secret: String,
    client_secret_secret: String,
) {
    create_provider(world, &provider_id, &token_endpoint, None, (&client_id_secret, &client_secret_secret)).await;
}

#[when(
    expr = "the operator creates the credential provider {string} for tenant {string} using secrets {string} and {string}"
)]
async fn operator_creates_tenant_provider(
    world: &mut SurfaceWorld,
    provider_id: String,
    tenant: String,
    client_id_secret: String,
    client_secret_secret: String,
) {
    create_provider(
        world,
        &provider_id,
        "https://192.0.2.1/token",
        Some(&tenant),
        (&client_id_secret, &client_secret_secret),
    )
    .await;
}

#[when(expr = "the operator creates the JWT Bearer provider {string} using the secret {string} with subject {string}")]
async fn operator_creates_jwt_bearer_provider_with_subject(
    world: &mut SurfaceWorld,
    provider_id: String,
    signing_key_secret: String,
    subject: String,
) {
    create_jwt_bearer_provider(world, &provider_id, &signing_key_secret, Some(&subject)).await;
}

#[when(
    expr = "the operator creates the JWT Bearer provider {string} using the secret {string} with subject {string}, authenticating its client with {string} with the client ID secret {string}"
)]
async fn operator_creates_jwt_bearer_provider_with_client_id_secret(
    world: &mut SurfaceWorld,
    provider_id: String,
    signing_key_secret: String,
    subject: String,
    authentication: String,
    client_id_secret: String,
) {
    let client = ClientAuthenticationFields {
        authentication: &authentication,
        client_id_secret: &client_id_secret,
        client_secret: None,
    };
    create_jwt_bearer_provider_authenticating_its_client(world, &provider_id, &signing_key_secret, &subject, client)
        .await;
}

#[when(
    expr = "the operator creates the JWT Bearer provider {string} using the secret {string} with subject {string}, authenticating its client with {string} with the client ID secret {string} and the client secret {string}"
)]
async fn operator_creates_jwt_bearer_provider_with_client_id_and_client_secret(
    world: &mut SurfaceWorld,
    provider_id: String,
    signing_key_secret: String,
    subject: String,
    authentication: String,
    client_id_secret: String,
    client_secret: String,
) {
    let client = ClientAuthenticationFields {
        authentication: &authentication,
        client_id_secret: &client_id_secret,
        client_secret: Some(&client_secret),
    };
    create_jwt_bearer_provider_authenticating_its_client(world, &provider_id, &signing_key_secret, &subject, client)
        .await;
}

#[when(expr = "the operator creates the JWT Bearer provider {string} using the secret {string} without a subject")]
async fn operator_creates_jwt_bearer_provider_without_subject(
    world: &mut SurfaceWorld,
    provider_id: String,
    signing_key_secret: String,
) {
    create_jwt_bearer_provider(world, &provider_id, &signing_key_secret, None).await;
}

#[when(expr = "the operator saves the surface authenticating its target with secret {string}")]
async fn operator_saves_surface_with_secret(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    let mut surface = stored_surface(world).await;
    surface["target"]["auth"] = static_secret(&secret_id);
    save_surface(world, &surface).await;
}

#[when(expr = "the operator saves the surface with the description {string}")]
async fn operator_saves_surface_with_description(
    world: &mut SurfaceWorld,
    description: String,
) {
    let mut surface = stored_surface(world).await;
    surface["description"] = json!(description);
    save_surface(world, &surface).await;
}

#[when(expr = "the operator reassigns the surface to tenant {string}")]
async fn operator_reassigns_surface(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    let path = format!("/v1/tenant-ownership/surfaces/{}", surface_id(world));
    let response = send(world, Method::PUT, &path, Some(&json!({"tenant_id": tenant}))).await;
    world.admin_response = Some(response);
}

#[when("the operator lists the credential providers")]
async fn operator_lists_credential_providers(world: &mut SurfaceWorld) {
    let response = send(world, Method::GET, "/v1/credential-providers", None).await;
    world.admin_response = Some(response);
}

#[then(expr = "the credential provider list shows the client authentication {string} for provider {string}")]
async fn provider_list_shows_client_authentication(
    world: &mut SurfaceWorld,
    authentication: String,
    provider_id: String,
) {
    let expected = TargetAuthClientAuthentication::from_wording(&authentication).api_value();
    let response = world
        .admin_response
        .as_ref()
        .expect("the operator listed the credential providers");
    assert_eq!(response.status, 200, "listing credential providers: {}", response.body);
    let provider = response
        .body
        .as_array()
        .expect("the provider list is an array")
        .iter()
        .find(|provider| provider["provider_id"] == provider_id)
        .unwrap_or_else(|| panic!("provider {provider_id} is not in the list: {}", response.body));
    assert_eq!(provider["client_authentication"], json!(expected), "the list entry: {provider}");
}

#[then(expr = "the credential provider {string} is stored")]
async fn credential_provider_is_stored(
    world: &mut SurfaceWorld,
    provider_id: String,
) {
    let ids = provider_ids(world).await;
    assert!(ids.contains(&provider_id), "provider {provider_id} is not among {ids:?}");
}

#[then(expr = "no credential provider {string} is stored")]
async fn no_credential_provider_is_stored(
    world: &mut SurfaceWorld,
    provider_id: String,
) {
    let ids = provider_ids(world).await;
    assert!(!ids.contains(&provider_id), "provider {provider_id} is stored among {ids:?}");
}

#[then(expr = "the stored surface authenticates its target with secret {string}")]
async fn stored_surface_authenticates_with_secret(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    let surface = stored_surface(world).await;
    assert_eq!(surface["target"]["auth"]["method"]["static_secret"]["secret_id"], secret_id, "{surface}");
}

#[then(expr = "the stored surface belongs to tenant {string}")]
async fn stored_surface_belongs_to_tenant(
    world: &mut SurfaceWorld,
    tenant: String,
) {
    let surface = stored_surface(world).await;
    assert_eq!(surface["tenant_id"], tenant, "{surface}");
}

#[then("the stored surface belongs to no tenant")]
async fn stored_surface_belongs_to_no_tenant(world: &mut SurfaceWorld) {
    let surface = stored_surface(world).await;
    assert!(surface["tenant_id"].is_null(), "{surface}");
}

#[then(expr = "the stored surface has the description {string}")]
async fn stored_surface_has_description(
    world: &mut SurfaceWorld,
    description: String,
) {
    let surface = stored_surface(world).await;
    assert_eq!(surface["description"], description, "{surface}");
}
