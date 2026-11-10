use std::time::Duration;

use base64::Engine;
use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::bdd_support::admin_client::{AdminApiClient, recorded_response};
use crate::bdd_support::gateway_process::SURFACE_TEST_AUTH_TOKEN;
use crate::bdd_support::passkey::SoftPasskey;
use crate::bdd_support::redis_stream::RedisStreamStandIn;
use crate::steps::when::{ensure_admin_session, ensure_gateway_running};
use crate::world::{StartedSignIn, SurfaceWorld};

/// How long a sign-in event may take to reach the Redis stream.
const EVENT_WAIT: Duration = Duration::from_secs(15);

/// The user variables of a sign-in event, as its `data` names them.
const USER_FIELDS: [&str; 5] = ["user_id", "username", "user_email", "user_role", "user_status"];

fn gateway_port(world: &SurfaceWorld) -> u16 {
    world
        .infra
        .as_ref()
        .expect("the gateway runs")
        .gateway_port
}

fn passkey_for(world: &SurfaceWorld) -> SoftPasskey {
    SoftPasskey::new("localhost", &format!("http://localhost:{}", gateway_port(world)))
}

async fn post_json(
    world: &SurfaceWorld,
    path: &str,
    body: &Value,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api{path}", gateway_port(world)))
        .json(body)
        .send()
        .await
        .unwrap_or_else(|error| panic!("POST {path}: {error}"))
}

/// The id of the console user `username`, read through the admin API.
async fn console_user_id(
    world: &mut SurfaceWorld,
    username: &str,
) -> String {
    ensure_admin_session(world).await;
    let users: Vec<Value> = world
        .admin_client
        .as_ref()
        .expect("admin session")
        .send_json::<(), _>(Method::GET, "/v1/users", None)
        .await
        .expect("list the console users");
    users
        .iter()
        .find(|user| user["username"] == username)
        .and_then(|user| user["user_id"].as_str())
        .unwrap_or_else(|| panic!("no console user {username:?} among {users:?}"))
        .to_string()
}

#[given("an integration streams sign-in events to Redis")]
async fn integration_streams_sign_in_events(world: &mut SurfaceWorld) {
    let stream = RedisStreamStandIn::start().await;
    world
        .surface_config
        .sign_in_event_stream = Some(stream.url());
    world.sign_in_stream = Some(stream);
}

#[given("console users sign in with SAML")]
fn console_users_sign_in_with_saml(world: &mut SurfaceWorld) {
    world
        .surface_config
        .signs_in_with_saml = true;
}

#[given(expr = "{string} is an approved console user")]
async fn approved_console_user(
    world: &mut SurfaceWorld,
    username: String,
) {
    ensure_gateway_running(world).await;
    AdminApiClient::new(gateway_port(world), SURFACE_TEST_AUTH_TOKEN, username)
        .bootstrap_test_session()
        .await
        .expect("the console user is provisioned");
}

#[given(expr = "{string} is an approved console user with a passkey")]
async fn approved_console_user_with_passkey(
    world: &mut SurfaceWorld,
    username: String,
) {
    ensure_admin_session(world).await;
    let passkey = passkey_for(world);
    let started: Value = post_json(world, "/auth/register/start", &json!({"username": username}))
        .await
        .json()
        .await
        .expect("a registration challenge");
    let finished = post_json(
        world,
        "/auth/register/finish",
        &json!({
            "challenge_id": started["challenge_id"],
            "credential": passkey.register(&started["creation_options"]),
        }),
    )
    .await;
    assert_eq!(finished.status(), reqwest::StatusCode::OK, "registering the passkey of {username}");
    let user_id = console_user_id(world, &username).await;
    let approved = world
        .admin_client
        .as_ref()
        .expect("admin session")
        .send_recorded_json(Method::PUT, &format!("/v1/users/{user_id}"), Some(&json!({"status": "approved"})))
        .await
        .expect("approve the console user");
    assert!((200..300).contains(&approved.status), "approving {username}: {}", approved.body);
    world.passkeys.insert(username, passkey);
}

async fn start_passkey_sign_in(
    world: &mut SurfaceWorld,
    username: String,
) {
    ensure_gateway_running(world).await;
    let started: Value = post_json(world, "/auth/login/start", &json!({"username": username}))
        .await
        .json()
        .await
        .expect("a sign-in challenge");
    world.started_sign_in = Some(StartedSignIn {
        username,
        challenge_id: started["challenge_id"]
            .as_str()
            .expect("a challenge id")
            .to_string(),
        request_options: started["request_options"].clone(),
    });
}

#[given(expr = "a passkey sign-in has been started for {string}")]
async fn passkey_sign_in_started(
    world: &mut SurfaceWorld,
    username: String,
) {
    start_passkey_sign_in(world, username).await;
}

#[given(expr = "a passkey sign-in has been started for the unknown username {string}")]
async fn passkey_sign_in_started_for_unknown_username(
    world: &mut SurfaceWorld,
    username: String,
) {
    start_passkey_sign_in(world, username).await;
}

async fn finish_sign_in(
    world: &mut SurfaceWorld,
    credential: Value,
) {
    let started = world
        .started_sign_in
        .take()
        .expect("a started sign-in");
    let response = post_json(
        world,
        "/auth/login/finish",
        &json!({"challenge_id": started.challenge_id, "credential": credential}),
    )
    .await;
    world.caller_response = Some(
        recorded_response(response)
            .await
            .expect("record the sign-in response"),
    );
}

#[when("the sign-in is finished with a passkey the gateway does not hold")]
async fn finish_with_unheld_passkey(world: &mut SurfaceWorld) {
    let mut passkey = passkey_for(world);
    let credential = passkey.sign_in(
        &world
            .started_sign_in
            .as_ref()
            .expect("a started sign-in")
            .request_options,
    );
    finish_sign_in(world, credential).await;
}

#[when("the sign-in is finished with the user's passkey")]
async fn finish_with_users_passkey(world: &mut SurfaceWorld) {
    let started = world
        .started_sign_in
        .as_ref()
        .expect("a started sign-in");
    let credential = world
        .passkeys
        .get_mut(&started.username)
        .unwrap_or_else(|| panic!("{} registered no passkey", started.username))
        .sign_in(&started.request_options);
    finish_sign_in(world, credential).await;
}

#[when("a SAML response the identity provider did not sign is posted to the gateway")]
async fn post_unsigned_saml_response(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let unsigned = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><saml:Subject><saml:NameID>member@example.test</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"#;
    let body = format!(
        "SAMLResponse={}",
        urlencoding::encode(&base64::engine::general_purpose::STANDARD.encode(unsigned))
    );
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/saml/acs", gateway_port(world)))
        .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .expect("POST the SAML response");
    world.caller_response = Some(
        recorded_response(response)
            .await
            .expect("record the SAML response's answer"),
    );
}

async fn receive_sign_in_event(
    world: &mut SurfaceWorld,
    event_type: &str,
    data: &[(&str, &str)],
) {
    let stream = world
        .sign_in_stream
        .as_ref()
        .expect("the Redis stream");
    let event = |entry: &crate::bdd_support::redis_stream::StreamEntry| {
        entry
            .field("data")
            .and_then(|payload| serde_json::from_str::<Value>(payload).ok())
    };
    let matches = |payload: &Value| {
        payload["event_type"] == event_type
            && data
                .iter()
                .all(|(name, value)| payload["data"][name] == *value)
    };
    let found = stream
        .wait_for(EVENT_WAIT, |entry| event(entry).is_some_and(|payload| matches(&payload)))
        .await;
    let received: Vec<Value> = stream
        .entries()
        .iter()
        .filter_map(event)
        .collect();
    let found = found.unwrap_or_else(|| {
        panic!("expected a {event_type} event with {data:?} on the Redis stream; it received {received:?}")
    });
    world.sign_in_event = event(&found);
}

#[then(expr = "the Redis stream receives a {string} event with login method {string}")]
async fn stream_receives_sign_in(
    world: &mut SurfaceWorld,
    event_type: String,
    method: String,
) {
    receive_sign_in_event(world, &event_type, &[("login_method", &method)]).await;
}

#[then(expr = "the Redis stream receives a {string} event with login method {string} and failure reason {string}")]
async fn stream_receives_failed_sign_in(
    world: &mut SurfaceWorld,
    event_type: String,
    method: String,
    reason: String,
) {
    receive_sign_in_event(world, &event_type, &[("login_method", &method), ("failure_reason", &reason)]).await;
}

fn sign_in_event(world: &SurfaceWorld) -> &Value {
    world
        .sign_in_event
        .as_ref()
        .expect("a sign-in event found on the Redis stream")
}

#[then(expr = "that event names the console user {string}")]
async fn event_names_console_user(
    world: &mut SurfaceWorld,
    username: String,
) {
    let user_id = console_user_id(world, &username).await;
    let data = &sign_in_event(world)["data"];
    assert_eq!(data["user_id"], user_id, "expected the event to name {username}'s id; it carries {data}");
    assert_eq!(data["username"], username, "{data}");
    assert_eq!(data["user_status"], "approved", "{data}");
}

#[then("that event names no user")]
fn event_names_no_user(world: &mut SurfaceWorld) {
    let data = &sign_in_event(world)["data"];
    for field in USER_FIELDS {
        assert!(data.get(field).is_none(), "expected no {field} in the event; it carries {data}");
    }
    assert_eq!(data["new_state"], Value::Null, "{data}");
}

#[then(expr = "that event does not contain {string}")]
fn event_does_not_contain(
    world: &mut SurfaceWorld,
    text: String,
) {
    let event = sign_in_event(world).to_string();
    assert!(!event.contains(&text), "expected the event not to contain {text:?}; it is {event}");
}
