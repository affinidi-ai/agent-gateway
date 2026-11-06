use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::bdd_support::config::single_surface_fixture::PROTECTED_RESOURCE_PUBLIC_ORIGIN;
use crate::steps::credential_references::provider_record_id;
use crate::steps::credential_save::{save_surface, send, stored_surface};
use crate::steps::when::build_primary_target_surface_payload;
use crate::world::SurfaceWorld;

const UNREACHABLE_HTTPS_TARGET: &str = "https://127.0.0.1:9/";
const UNREACHABLE_HTTP_TARGET: &str = "http://127.0.0.1:9/";

fn static_secret(
    secret_id: &str,
    header_name: &str,
) -> Value {
    json!({"method": {"static_secret": {
        "secret_id": secret_id, "header_name": header_name, "header_format": "{value}"
    }}})
}

fn draft(world: &mut SurfaceWorld) -> &mut Value {
    world
        .surface_draft
        .as_mut()
        .expect("a surface draft must be prepared first")
}

fn draft_transit_point<'a>(
    world: &'a mut SurfaceWorld,
    alias: &str,
) -> &'a mut Value {
    draft(world)["transit"]["points"]
        .as_array_mut()
        .and_then(|points| {
            points
                .iter_mut()
                .find(|point| point["alias"] == alias)
        })
        .unwrap_or_else(|| panic!("the draft has no Transit Point {alias}"))
}

fn header_format_mut(target_auth: &mut Value) -> &mut Value {
    &mut target_auth["method"]["static_secret"]["header_format"]
}

/// The draft's Target is the scenario's managed agent, served over plain http, and its Access
/// Point has no caller authentication and no `public`, so the gateway closes it; each scenario
/// states the Target URL and caller check it relies on.
#[given(expr = "a surface draft for route {string} whose Target receives secret {string} in header {string}")]
async fn surface_draft_with_target_auth(
    world: &mut SurfaceWorld,
    route: String,
    secret_id: String,
    header_name: String,
) {
    let mut payload = build_primary_target_surface_payload(world, &route).await;
    payload["name"] = json!(route.trim_start_matches('/'));
    payload["status"] = json!("disabled");
    payload["target"]["auth"] = static_secret(&secret_id, &header_name);
    payload["access_point"]
        .as_object_mut()
        .expect("the draft has an Access Point")
        .remove("public");
    world.surface_draft = Some(payload);
}

/// The draft's Access Point checks JWT Bearer tokens without naming an audience, and its Target
/// takes no credential.
#[given(expr = "a surface draft for route {string} whose Access Point checks JWT Bearer tokens naming no audience")]
async fn surface_draft_checking_jwt_without_audience(
    world: &mut SurfaceWorld,
    route: String,
) {
    let mut payload = build_primary_target_surface_payload(world, &route).await;
    payload["name"] = json!(route.trim_start_matches('/'));
    payload["status"] = json!("disabled");
    let strategy_id = create_caller_jwt_strategy(world).await;
    payload["access_point"]["caller_authentication"] = json!({"methods": [{
        "type": "jwt_bearer", "jwt_verification_strategy_id": strategy_id, "audiences": []
    }]});
    world.surface_draft = Some(payload);
}

#[given("the draft's Target is an https URL")]
fn draft_target_is_https(world: &mut SurfaceWorld) {
    draft(world)["target"]["endpoint"] = json!(UNREACHABLE_HTTPS_TARGET);
}

#[given(expr = "the draft's Access Point checks callers by the API key in secret {string}")]
fn draft_access_point_checks_callers(
    world: &mut SurfaceWorld,
    secret_id: String,
) {
    draft(world)["access_point"]["caller_authentication"] = json!({"methods": [{
        "type": "api_key", "secret_id": secret_id,
        "extraction": {"source": "http_header", "field": "X-Caller-Key"}
    }]});
}

#[given("the draft's Access Point is closed")]
fn draft_access_point_is_closed(world: &mut SurfaceWorld) {
    draft(world)["access_point"]["public"] = json!(false);
}

#[given(expr = "the draft's Target authentication formats its value as {string}")]
fn draft_target_auth_format(
    world: &mut SurfaceWorld,
    format: String,
) {
    *header_format_mut(&mut draft(world)["target"]["auth"]) = json!(format);
}

#[given(regex = r#"^the draft's Target authentication formats its value as "([^"]*)" followed by a (CR|LF|NUL)$"#)]
fn draft_target_auth_format_with_control_character(
    world: &mut SurfaceWorld,
    format: String,
    character: String,
) {
    let control = match character.as_str() {
        "CR" => '\r',
        "LF" => '\n',
        _ => '\0',
    };
    *header_format_mut(&mut draft(world)["target"]["auth"]) = json!(format!("{format}{control}"));
}

#[given(expr = "the draft's Target is {string}")]
fn draft_target_endpoint(
    world: &mut SurfaceWorld,
    endpoint: String,
) {
    draft(world)["target"]["endpoint"] = json!(endpoint);
}

#[given("the draft's Access Point does not check its callers")]
fn draft_access_point_checks_no_caller(world: &mut SurfaceWorld) {
    draft(world)["access_point"]
        .as_object_mut()
        .expect("the draft has an Access Point")
        .remove("caller_authentication");
}

#[given(expr = "the draft's Access Point maps caller header {string} to metadata field {string}")]
fn draft_access_point_maps_header(
    world: &mut SurfaceWorld,
    header: String,
    field: String,
) {
    draft(world)["access_point"]["header_metadata_mapping"] = json!({"headers": [{"header": header, "field": field}]});
}

#[given(expr = "the draft injects a delegated credential from credential provider {string} as header {string}")]
async fn draft_injects_delegated_credential(
    world: &mut SurfaceWorld,
    provider_id: String,
    header: String,
) {
    let provider = provider_record_id(world, &provider_id).await;
    draft(world)["outbound_credentials"] = json!([{
        "credential_provider_id": provider,
        "inject_as": {"type": "custom_header", "name": header, "format": "{value}"}
    }]);
}

/// Creates the JWT verification strategy a draft's caller check names, through the admin API.
async fn create_caller_jwt_strategy(world: &mut SurfaceWorld) -> Value {
    let strategy = json!({
        "name": "BDD caller IdP",
        "expected_issuer": "https://issuer.bdd.example",
        "jwks_source": {"type": "static", "jwks": [crate::bdd_support::jwt::public_jwk()]},
    });
    let created = send(world, Method::POST, "/v1/jwt-verification-strategies", Some(&strategy)).await;
    assert_eq!(created.status, 201, "creating the JWT verification strategy: {}", created.body);
    created.body["id"].clone()
}

#[given(expr = "the draft's Access Point forwards the caller's JWT Bearer token in header {string}")]
async fn draft_forwards_caller_jwt(
    world: &mut SurfaceWorld,
    header: String,
) {
    let strategy_id = create_caller_jwt_strategy(world).await;
    draft(world)["access_point"]["caller_authentication"] = json!({"methods": [{
        "type": "jwt_bearer", "jwt_verification_strategy_id": strategy_id, "audiences": ["api://agent"],
        "token_header": header, "forward_header": true
    }]});
}

/// The Transit Point requires no transit token, has no `source_auth`, `mcp_http` or
/// `allow_unauthenticated_callers`, and reaches a plain http target endpoint; each scenario
/// states the caller check and target endpoint it relies on.
#[given(expr = "the draft has Transit Point {string} that sends secret {string} in header {string}")]
fn draft_has_transit_point(
    world: &mut SurfaceWorld,
    alias: String,
    secret_id: String,
    header_name: String,
) {
    let point = json!({
        "id": format!("{alias}-id"), "alias": alias, "name": alias, "protocol": "a2a",
        "target_endpoint": UNREACHABLE_HTTP_TARGET, "listen_path": format!("/transit/{alias}"),
        "require_transit_token": false, "target_auth": static_secret(&secret_id, &header_name)
    });
    let surface = draft(world);
    if surface["transit"]["points"].is_array() {
        surface["transit"]["points"]
            .as_array_mut()
            .expect("the draft's Transit Points are a list")
            .push(point);
    } else {
        surface["transit"] = json!({"points": [point]});
    }
}

#[given(expr = "Transit Point {string} in the draft requires a transit token")]
fn draft_transit_point_requires_transit_token(
    world: &mut SurfaceWorld,
    alias: String,
) {
    draft_transit_point(world, &alias)["require_transit_token"] = json!(true);
}

#[given(expr = "Transit Point {string} in the draft checks callers by the API key in secret {string}")]
fn draft_transit_point_checks_callers_by_api_key(
    world: &mut SurfaceWorld,
    alias: String,
    secret_id: String,
) {
    draft_transit_point(world, &alias)["source_auth"] = json!({
        "type": "api_key", "secret_id": secret_id,
        "extraction": {"source": "http_header", "field": "X-Agent-Key"}
    });
}

#[given("the gateway publishes its Transit Point listener at an https address")]
fn gateway_publishes_transit_listener_at_https_origin(world: &mut SurfaceWorld) {
    assert!(world.infra.is_none(), "the Transit Point listener's address must be set before the gateway starts");
    world
        .surface_config
        .outbound_public_origin = true;
}

#[given(expr = "Transit Point {string} in the draft is an MCP Transit Point that checks callers' MCP authorization")]
fn draft_transit_point_checks_mcp_authorization(
    world: &mut SurfaceWorld,
    alias: String,
) {
    let outbound = format!(
        "http://localhost:{}",
        world
            .infra
            .as_ref()
            .expect("the gateway runs once the draft exists")
            .outbound_port
    );
    draft(world)["transit"]["outbound_listen_address"] = json!(outbound);
    let point = draft_transit_point(world, &alias);
    point["protocol"] = json!("mcp");
    point["mcp_http"] =
        json!({"authorization": {"resource": format!("{PROTECTED_RESOURCE_PUBLIC_ORIGIN}/transit/{alias}")}});
}

#[given(expr = "the target endpoint of Transit Point {string} in the draft is an https URL")]
fn draft_transit_point_endpoint_is_https(
    world: &mut SurfaceWorld,
    alias: String,
) {
    draft_transit_point(world, &alias)["target_endpoint"] = json!(UNREACHABLE_HTTPS_TARGET);
}

#[given(expr = "Transit Point {string} in the draft is an Open Transit Point")]
fn draft_transit_point_checks_no_caller(
    world: &mut SurfaceWorld,
    alias: String,
) {
    let point = draft_transit_point(world, &alias);
    point["require_transit_token"] = json!(false);
    point["allow_unauthenticated_callers"] = json!(true);
}

#[given(expr = "the target endpoint of Transit Point {string} in the draft is {string}")]
fn draft_transit_point_endpoint(
    world: &mut SurfaceWorld,
    alias: String,
    endpoint: String,
) {
    draft_transit_point(world, &alias)["target_endpoint"] = json!(endpoint);
}

#[given(expr = "the Target authentication of Transit Point {string} in the draft formats its value as {string}")]
fn draft_transit_point_target_auth_format(
    world: &mut SurfaceWorld,
    alias: String,
    format: String,
) {
    *header_format_mut(&mut draft_transit_point(world, &alias)["target_auth"]) = json!(format);
}

#[given(expr = "Transit Point {string} in the draft has the id of Transit Point {string}")]
fn draft_transit_point_reuses_id(
    world: &mut SurfaceWorld,
    alias: String,
    other: String,
) {
    let id = draft_transit_point(world, &other)["id"].clone();
    draft_transit_point(world, &alias)["id"] = id;
}

async fn create_surface_from_draft(world: &mut SurfaceWorld) {
    let payload = world
        .surface_draft
        .clone()
        .expect("a surface draft must be prepared first");
    let response = send(world, Method::POST, "/v1/surfaces", Some(&payload)).await;
    world.admin_response = Some(response);
}

#[when("the operator creates the surface from the draft")]
async fn operator_creates_surface_from_draft(world: &mut SurfaceWorld) {
    create_surface_from_draft(world).await;
}

#[given("the operator has created the surface from the draft")]
async fn operator_has_created_surface_from_draft(world: &mut SurfaceWorld) {
    create_surface_from_draft(world).await;
    let response = world
        .admin_response
        .take()
        .expect("the admin API must answer");
    assert_eq!(response.status, 201, "creating the surface from the draft: {}", response.body);
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

#[when(expr = "the operator saves the surface reading the caller's JWT Bearer token from header {string}")]
async fn operator_saves_surface_reading_jwt_from_header(
    world: &mut SurfaceWorld,
    header: String,
) {
    let mut surface = stored_surface(world).await;
    let method = surface["access_point"]["caller_authentication"]["methods"]
        .as_array_mut()
        .and_then(|methods| {
            methods
                .iter_mut()
                .find(|method| method["type"] == "jwt_bearer")
        })
        .expect("the stored surface checks callers with JWT Bearer");
    method["token_header"] = json!(header);
    save_surface(world, &surface).await;
}

#[when("the operator saves the surface without its Access Point's caller check")]
async fn operator_saves_surface_without_caller_check(world: &mut SurfaceWorld) {
    let mut surface = stored_surface(world).await;
    surface["access_point"]
        .as_object_mut()
        .expect("the stored surface has an Access Point")
        .remove("caller_authentication");
    save_surface(world, &surface).await;
}

#[when(expr = "the operator saves the surface with its Target moved to {string}")]
async fn operator_saves_surface_with_target_moved(
    world: &mut SurfaceWorld,
    endpoint: String,
) {
    let mut surface = stored_surface(world).await;
    surface["target"]["endpoint"] = json!(endpoint);
    save_surface(world, &surface).await;
}

#[when(expr = "the operator saves the surface with Transit Point {string} taking the id of Transit Point {string}")]
async fn operator_saves_surface_with_duplicate_transit_point_id(
    world: &mut SurfaceWorld,
    alias: String,
    other: String,
) {
    let mut surface = stored_surface(world).await;
    let points = surface["transit"]["points"]
        .as_array_mut()
        .expect("the stored surface has Transit Points");
    let id = points
        .iter()
        .find(|point| point["alias"] == other.as_str())
        .unwrap_or_else(|| panic!("the stored surface has no Transit Point {other}"))["id"]
        .clone();
    points
        .iter_mut()
        .find(|point| point["alias"] == alias.as_str())
        .unwrap_or_else(|| panic!("the stored surface has no Transit Point {alias}"))["id"] = id;
    save_surface(world, &surface).await;
}

#[when(expr = "the operator saves the surface with its Target authentication formatting the value as {string}")]
async fn operator_saves_surface_with_header_format(
    world: &mut SurfaceWorld,
    format: String,
) {
    let mut surface = stored_surface(world).await;
    *header_format_mut(&mut surface["target"]["auth"]) = json!(format);
    save_surface(world, &surface).await;
}

#[when(
    expr = "the operator saves the surface with the Target authentication of Transit Point {string} falling back to {string}"
)]
async fn operator_saves_transit_point_target_auth_fallback(
    world: &mut SurfaceWorld,
    alias: String,
    fallback: String,
) {
    let mut surface = stored_surface(world).await;
    let point = surface["transit"]["points"]
        .as_array_mut()
        .and_then(|points| {
            points
                .iter_mut()
                .find(|point| point["alias"] == alias.as_str())
        })
        .unwrap_or_else(|| panic!("the stored surface has no Transit Point {alias}"));
    point["target_auth"]["fallback"] = json!(fallback);
    save_surface(world, &surface).await;
}

fn admin_response_warnings(world: &SurfaceWorld) -> Vec<String> {
    let response = world
        .admin_response
        .as_ref()
        .expect("the operator must have received an admin API response");
    response
        .headers
        .get("warning")
        .map(|warnings| {
            warnings
                .lines()
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[then(expr = "the admin API response carries a Warning header containing {string}")]
fn admin_response_carries_warning(
    world: &mut SurfaceWorld,
    text: String,
) {
    let warnings = admin_response_warnings(world);
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains(&text)),
        "expected a Warning header containing {text:?}, got {warnings:?}"
    );
}

#[then(expr = "the admin API response carries no Warning header containing {string}")]
fn admin_response_carries_no_warning(
    world: &mut SurfaceWorld,
    text: String,
) {
    let warnings = admin_response_warnings(world);
    assert!(
        !warnings
            .iter()
            .any(|warning| warning.contains(&text)),
        "expected no Warning header containing {text:?}, got {warnings:?}"
    );
}
