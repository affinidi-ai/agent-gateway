//! Steps for JWT verification strategy authorization server discovery: the
//! operator discovers an authorization server's metadata through the admin API
//! and pins, keeps or clears it on a strategy.

use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::bdd_support::admin_client::AdminApiClient;
use crate::bdd_support::assertions::{assert_json_body_does_not_mention, assert_status_with_body};
use crate::bdd_support::authz_metadata_server::{AuthorizationServer, MetadataPublication};
use crate::bdd_support::config::jwt_verification_strategy::{
    STRATEGY_KEY_SET_URI, jwt_verification_strategy_request, remote_jwks_source,
};
use crate::bdd_support::gateway_process::SURFACE_TEST_AUTH_TOKEN;
use crate::steps::when::{ensure_admin_session, ensure_gateway_running};
use crate::world::{RecordedResponse, SurfaceSourceAuthConfig, SurfaceWorld};

const STRATEGIES_PATH: &str = "/v1/jwt-verification-strategies";
const DISCOVER_PATH: &str = "/v1/jwt-verification-strategies/discover";

fn publication(phrase: &str) -> MetadataPublication {
    match phrase {
        "publishes OAuth authorization server metadata" => MetadataPublication::OAuthAuthorizationServer,
        "publishes an OpenID Connect configuration" => MetadataPublication::OpenIdConfiguration,
        "does not publish metadata" => MetadataPublication::Absent,
        "publishes metadata naming another issuer" => MetadataPublication::ForeignIssuer,
        "publishes an oversized metadata document" => MetadataPublication::Oversized,
        "publishes a metadata document without a key set" => MetadataPublication::WithoutKeySet,
        other => panic!("unsupported authorization server publication '{other}'"),
    }
}

fn authorization_server<'a>(
    world: &'a SurfaceWorld,
    name: &str,
) -> &'a AuthorizationServer {
    world
        .authorization_servers
        .get(name)
}

async fn operator_client(world: &mut SurfaceWorld) -> AdminApiClient {
    ensure_admin_session(world).await;
    world
        .admin_client
        .clone()
        .expect("the operator's admin session exists")
}

async fn send(
    client: &AdminApiClient,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> RecordedResponse {
    client
        .send_recorded_json(method.clone(), path, body)
        .await
        .unwrap_or_else(|error| panic!("{method} {path}: {error}"))
}

async fn stored_strategies(world: &mut SurfaceWorld) -> Vec<Value> {
    let client = operator_client(world).await;
    let response = send(&client, Method::GET, STRATEGIES_PATH, None).await;
    assert_status_with_body(response.status, 200, &response.body, "strategy list");
    response
        .body
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("the strategy list is an array, got {}", response.body))
}

async fn stored_strategy_id(
    world: &mut SurfaceWorld,
    name: &str,
) -> Option<String> {
    stored_strategies(world)
        .await
        .into_iter()
        .find(|strategy| strategy["name"] == name)
        .map(|strategy| {
            strategy["id"]
                .as_str()
                .expect("a stored strategy has an id")
                .to_string()
        })
}

async fn read_strategy_by_id(
    world: &mut SurfaceWorld,
    id: &str,
) -> Value {
    let client = operator_client(world).await;
    let response = send(&client, Method::GET, &format!("{STRATEGIES_PATH}/{id}"), None).await;
    assert_status_with_body(response.status, 200, &response.body, "strategy read");
    response.body
}

async fn read_strategy(
    world: &mut SurfaceWorld,
    name: &str,
) -> Value {
    let id = stored_strategy_id(world, name)
        .await
        .unwrap_or_else(|| panic!("JWT verification strategy '{name}' is not stored"));
    read_strategy_by_id(world, &id).await
}

async fn create_strategy(
    world: &mut SurfaceWorld,
    name: &str,
    issuer: &str,
) -> RecordedResponse {
    let client = operator_client(world).await;
    let request = jwt_verification_strategy_request(name, issuer, remote_jwks_source(STRATEGY_KEY_SET_URI), Some(true));
    send(&client, Method::POST, STRATEGIES_PATH, Some(&request)).await
}

async fn save_strategy(
    world: &mut SurfaceWorld,
    stored: &Value,
    issuer: &str,
    discover_metadata: Option<bool>,
) -> RecordedResponse {
    let client = operator_client(world).await;
    let id = stored["id"]
        .as_str()
        .expect("a stored strategy has an id");
    let name = stored["name"]
        .as_str()
        .expect("a stored strategy has a name");
    let request = jwt_verification_strategy_request(name, issuer, stored["jwks_source"].clone(), discover_metadata);
    send(&client, Method::PUT, &format!("{STRATEGIES_PATH}/{id}"), Some(&request)).await
}

async fn discover_with(
    client: &AdminApiClient,
    issuer: String,
) -> RecordedResponse {
    send(client, Method::POST, DISCOVER_PATH, Some(&json!({ "issuer": issuer }))).await
}

fn admin_response(world: &SurfaceWorld) -> &RecordedResponse {
    world
        .admin_response
        .as_ref()
        .expect("a When must record the admin API response before this Then")
}

#[given(
    regex = r#"^authorization server "([^"]+)" (publishes OAuth authorization server metadata|publishes an OpenID Connect configuration|does not publish metadata|publishes metadata naming another issuer|publishes an oversized metadata document|publishes a metadata document without a key set)$"#
)]
async fn authorization_server_publishes(
    world: &mut SurfaceWorld,
    name: String,
    phrase: String,
) {
    world
        .authorization_servers
        .publish(&name, publication(&phrase))
        .await;
}

#[given(expr = "JWT verification strategy {string} is pinned to authorization server {string}")]
async fn strategy_is_pinned(
    world: &mut SurfaceWorld,
    name: String,
    server: String,
) {
    let issuer = authorization_server(world, &server).issuer();
    let response = create_strategy(world, &name, &issuer).await;
    assert_status_with_body(response.status, 201, &response.body, "pinned strategy setup");
    assert_eq!(
        response.body["authorization_server"],
        authorization_server(world, &server).published_metadata(),
        "pinned strategy setup"
    );
}

#[given(expr = "the surface's JWT verification strategy trusts authorization server {string} and pins its metadata")]
fn surface_strategy_trusts_and_pins(
    world: &mut SurfaceWorld,
    server: String,
) {
    assert!(
        matches!(
            world
                .surface_config
                .source_auth,
            Some(SurfaceSourceAuthConfig::JwtBearer(_))
        ),
        "the surface must require JWT Bearer source authentication"
    );
    let pin = authorization_server(world, &server).published_metadata();
    world
        .surface_config
        .jwt_strategy_authorization_server = Some(pin);
}

#[when(expr = "the operator discovers the metadata of authorization server {string}")]
async fn operator_discovers(
    world: &mut SurfaceWorld,
    server: String,
) {
    let issuer = authorization_server(world, &server).issuer();
    let client = operator_client(world).await;
    world.admin_response = Some(discover_with(&client, issuer).await);
}

#[when(expr = "operator {string} discovers the metadata of authorization server {string}")]
async fn named_operator_discovers(
    world: &mut SurfaceWorld,
    operator: String,
    server: String,
) {
    let issuer = authorization_server(world, &server).issuer();
    let client = world
        .operator_clients
        .get(&operator)
        .cloned()
        .unwrap_or_else(|| panic!("operator '{operator}' has no admin session"));
    world.admin_response = Some(discover_with(&client, issuer).await);
}

#[when(expr = "a client without a session asks to discover the metadata of authorization server {string}")]
async fn client_without_session_discovers(
    world: &mut SurfaceWorld,
    server: String,
) {
    ensure_gateway_running(world).await;
    let issuer = authorization_server(world, &server).issuer();
    let gateway_port = world
        .infra
        .as_ref()
        .expect("scenario infra must exist")
        .gateway_port;
    let client = AdminApiClient::new(gateway_port, SURFACE_TEST_AUTH_TOKEN, "surface-bdd-no-session");
    world.admin_response = Some(discover_with(&client, issuer).await);
}

#[when(
    expr = "the operator creates JWT verification strategy {string} for authorization server {string} with discovery"
)]
async fn operator_creates_strategy_for_server(
    world: &mut SurfaceWorld,
    name: String,
    server: String,
) {
    let issuer = authorization_server(world, &server).issuer();
    world.admin_response = Some(create_strategy(world, &name, &issuer).await);
}

#[when(expr = "the operator creates JWT verification strategy {string} with issuer {string} and discovery")]
async fn operator_creates_strategy_with_issuer(
    world: &mut SurfaceWorld,
    name: String,
    issuer: String,
) {
    world.admin_response = Some(create_strategy(world, &name, &issuer).await);
}

#[when(expr = "the operator saves JWT verification strategy {string} with discovery turned off")]
async fn operator_saves_without_discovery(
    world: &mut SurfaceWorld,
    name: String,
) {
    let stored = read_strategy(world, &name).await;
    let issuer = stored["expected_issuer"]
        .as_str()
        .expect("a stored strategy has an issuer")
        .to_string();
    world.admin_response = Some(save_strategy(world, &stored, &issuer, Some(false)).await);
}

#[when(expr = "the operator moves JWT verification strategy {string} to the issuer of authorization server {string}")]
async fn operator_moves_strategy(
    world: &mut SurfaceWorld,
    name: String,
    server: String,
) {
    let issuer = authorization_server(world, &server).issuer();
    let stored = read_strategy(world, &name).await;
    world.admin_response = Some(save_strategy(world, &stored, &issuer, None).await);
}

#[then(expr = "the discovered metadata matches the published metadata of authorization server {string}")]
fn discovered_metadata_matches(
    world: &mut SurfaceWorld,
    server: String,
) {
    assert_eq!(
        admin_response(world).body,
        authorization_server(world, &server).published_metadata(),
        "expected the discovered metadata (left) to equal what authorization server '{server}' published (right)"
    );
}

#[then(expr = "no JWT verification strategy is stored for authorization server {string}")]
async fn no_strategy_for_server(
    world: &mut SurfaceWorld,
    server: String,
) {
    let issuer = authorization_server(world, &server).issuer();
    let matching: Vec<Value> = stored_strategies(world)
        .await
        .into_iter()
        .filter(|strategy| strategy["expected_issuer"] == issuer.as_str())
        .collect();
    assert!(matching.is_empty(), "expected no strategy for issuer {issuer}, found {matching:?}");
}

#[then(expr = "JWT verification strategy {string} is not stored")]
async fn strategy_is_not_stored(
    world: &mut SurfaceWorld,
    name: String,
) {
    let id = stored_strategy_id(world, &name).await;
    assert_eq!(id, None, "expected JWT verification strategy '{name}' not to be stored");
}

#[then(expr = "the admin API error code is {string}")]
fn admin_api_error_code_is(
    world: &mut SurfaceWorld,
    expected: String,
) {
    let body = &admin_response(world).body;
    assert_eq!(body["code"], expected.as_str(), "admin API error {body}");
}

#[then(expr = "the admin API error does not reveal the address of authorization server {string}")]
fn admin_api_error_does_not_reveal_address(
    world: &mut SurfaceWorld,
    server: String,
) {
    let body = &admin_response(world).body;
    let mut fields: Vec<&str> = body
        .as_object()
        .unwrap_or_else(|| panic!("the admin API error is a JSON object, got {body}"))
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(fields, vec!["code", "error"], "admin API error {body}");
    let server = authorization_server(world, &server);
    for revealing in [server.address(), server.port().to_string(), "://".to_string(), "404".to_string()] {
        assert_json_body_does_not_mention(body, &revealing, "admin API error");
    }
}

#[then(expr = "JWT verification strategy {string} pins the published metadata of authorization server {string}")]
async fn strategy_pins_published_metadata(
    world: &mut SurfaceWorld,
    name: String,
    server: String,
) {
    let stored = read_strategy(world, &name).await;
    let expected = authorization_server(world, &server).published_metadata();
    assert_eq!(stored["authorization_server"], expected, "stored strategy {stored}");
    assert_eq!(stored["expected_issuer"], expected["issuer"], "stored strategy {stored}");
}

#[then(expr = "JWT verification strategy {string} reads its keys from its own key set")]
async fn strategy_reads_its_own_key_set(
    world: &mut SurfaceWorld,
    name: String,
) {
    let stored = read_strategy(world, &name).await;
    assert_eq!(stored["jwks_source"], remote_jwks_source(STRATEGY_KEY_SET_URI), "stored strategy {stored}");
}

#[then(expr = "JWT verification strategy {string} has no pinned authorization server")]
async fn strategy_has_no_pin(
    world: &mut SurfaceWorld,
    name: String,
) {
    let stored = read_strategy(world, &name).await;
    assert!(
        stored
            .get("authorization_server")
            .is_none(),
        "expected no pin on stored strategy {stored}"
    );
}

#[then(expr = "JWT verification strategy {string} expects the issuer of authorization server {string}")]
async fn strategy_expects_issuer(
    world: &mut SurfaceWorld,
    name: String,
    server: String,
) {
    let stored = read_strategy(world, &name).await;
    let issuer = authorization_server(world, &server).issuer();
    assert_eq!(stored["expected_issuer"], issuer.as_str(), "stored strategy {stored}");
}

#[then(expr = "authorization server {string} received no request")]
fn authorization_server_received_no_request(
    world: &mut SurfaceWorld,
    server: String,
) {
    let requests = authorization_server(world, &server).requests();
    assert!(requests.is_empty(), "expected authorization server '{server}' to receive no request, got {requests:?}");
}

#[then(expr = "authorization server {string} received no request for its key set")]
fn authorization_server_received_no_key_set_request(
    world: &mut SurfaceWorld,
    server: String,
) {
    assert_eq!(
        authorization_server(world, &server).key_set_request_count(),
        0,
        "expected authorization server '{server}' to receive no request for its key set, got {:?}",
        authorization_server(world, &server).requests()
    );
}
