use std::time::Duration;

use base64::Engine;
use cucumber::{given, then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::bdd_support::admin_client::{AdminApiClient, recorded_response};
use crate::bdd_support::gateway_process::SURFACE_TEST_AUTH_TOKEN;
use crate::bdd_support::passkey::SoftPasskey;
use crate::bdd_support::redis_stream::RedisStreamStandIn;
use crate::bdd_support::sign_in_events::{
    ACCOUNT_DATA_FIELDS, APPLIANCE_ID, ENVELOPE_FIELDS, EVENT_TOPIC, NO_ACCOUNT_DATA_FIELDS, RECORD_FIELDS,
    RECORD_TOPIC, STATE_FIELDS, golden, golden_path, keys, names, normalise, updates_golden, write_golden,
};
use crate::steps::when::{ensure_admin_session, ensure_gateway_running};
use crate::world::{StartedSignIn, SurfaceWorld};

/// How long a sign-in event may take to reach the stream.
const EVENT_WAIT: Duration = Duration::from_secs(15);

/// How long after the first event a second one of the same sign-in is looked for. A delivery is
/// made at once and its first retry follows 1 second plus at most 1 second of jitter, so a
/// duplicate from a retry arrives within this wait.
const EXACTLY_ONCE_WAIT: Duration = Duration::from_secs(2);

/// How long a sign-in that raises nothing is watched for an event. A raised event reaches the
/// stream in milliseconds.
const NO_EVENT_WAIT: Duration = Duration::from_secs(3);

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

/// The stored account of the console user `username`, read through the admin API.
async fn console_user(
    world: &mut SurfaceWorld,
    username: &str,
) -> Value {
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
        .cloned()
        .unwrap_or_else(|| panic!("no console user {username:?} among {users:?}"))
}

/// Registers a passkey for the new console user `username`, who then awaits approval, and
/// returns the user's id.
async fn register_passkey(
    world: &mut SurfaceWorld,
    username: String,
) -> String {
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
    let stored = console_user(world, &username).await;
    assert_eq!(stored["status"], "new", "a registered user awaits approval: {stored}");
    world
        .passkeys
        .insert(username, passkey);
    stored["user_id"]
        .as_str()
        .expect("a user id")
        .to_string()
}

#[given("an integration whose event set holds the sign-in events")]
async fn integration_streams_sign_in_events(world: &mut SurfaceWorld) {
    let stream = RedisStreamStandIn::start().await;
    world
        .surface_config
        .sign_in_event_stream = Some(stream.url());
    world.sign_in_stream = Some(stream);
}

#[given("human users sign in with SAML")]
fn console_users_sign_in_with_saml(world: &mut SurfaceWorld) {
    world
        .surface_config
        .signs_in_with_saml = true;
}

#[given(expr = "human user {string} is approved")]
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

#[given(expr = "human user {string} is approved and has a passkey")]
async fn approved_console_user_with_passkey(
    world: &mut SurfaceWorld,
    username: String,
) {
    let user_id = register_passkey(world, username.clone()).await;
    let approved = world
        .admin_client
        .as_ref()
        .expect("admin session")
        .send_recorded_json(Method::PUT, &format!("/v1/users/{user_id}"), Some(&json!({"status": "approved"})))
        .await
        .expect("approve the console user");
    assert!((200..300).contains(&approved.status), "approving {username}: {}", approved.body);
}

#[given(expr = "human user {string} has registered a passkey and awaits approval")]
async fn console_user_awaiting_approval(
    world: &mut SurfaceWorld,
    username: String,
) {
    register_passkey(world, username).await;
}

#[given("another integration uses Agent Watch's template")]
fn integration_streams_sign_in_records(world: &mut SurfaceWorld) {
    world
        .surface_config
        .streams_sign_in_records = true;
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

#[given(expr = "a passkey sign-in has been started for human user {string}")]
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

#[when("the sign-in is completed with a passkey that is not the user's")]
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

#[when("the sign-in is completed with the user's passkey")]
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
    let body =
        format!("SAMLResponse={}", urlencoding::encode(&base64::engine::general_purpose::STANDARD.encode(unsigned)));
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

#[when("a passkey sign-in is completed without a sign-in the gateway started")]
async fn finish_with_unissued_challenge(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let mut passkey = passkey_for(world);
    let credential = passkey.sign_in(&json!({"publicKey": {"challenge": "AAAAAAAAAAAAAAAAAAAAAA"}}));
    world.started_sign_in = Some(StartedSignIn {
        username: String::new(),
        challenge_id: uuid::Uuid::new_v4().to_string(),
        request_options: Value::Null,
    });
    finish_sign_in(world, credential).await;
}

/// The payloads streamed to `topic`, each the `data` field of a stream entry, in order.
fn payloads(
    world: &SurfaceWorld,
    topic: &str,
) -> Vec<Value> {
    world
        .sign_in_stream
        .as_ref()
        .expect("the stream")
        .entries()
        .iter()
        .filter(|entry| entry.stream == topic)
        .filter_map(|entry| entry.field("data"))
        .map(|payload| serde_json::from_str(payload).unwrap_or_else(|error| panic!("{error}: {payload}")))
        .collect()
}

/// Waits for a `event_type` payload on `topic` whose event data, under `data_field`, holds `data`.
async fn receive_sign_in_payload(
    world: &SurfaceWorld,
    topic: &str,
    data_field: &str,
    event_type: &str,
    data: &[(&str, &str)],
) -> Value {
    let matches = |payload: &Value| {
        payload["event_type"] == event_type
            && data
                .iter()
                .all(|(name, value)| payload[data_field][name] == *value)
    };
    let found = world
        .sign_in_stream
        .as_ref()
        .expect("the stream")
        .wait_for(EVENT_WAIT, |entry| {
            entry.stream == topic
                && entry
                    .field("data")
                    .and_then(|payload| serde_json::from_str::<Value>(payload).ok())
                    .is_some_and(|payload| matches(&payload))
        })
        .await;
    let found = found.unwrap_or_else(|| {
        panic!(
            "expected a {event_type} payload with {data:?} under {data_field} on {topic}; it received {:?}",
            payloads(world, topic)
        )
    });
    serde_json::from_str(
        found
            .field("data")
            .expect("a payload"),
    )
    .expect("a JSON payload")
}

#[then(expr = "the integration receives a {string} event with login method {string}")]
async fn stream_receives_sign_in(
    world: &mut SurfaceWorld,
    event_type: String,
    method: String,
) {
    world.sign_in_event =
        Some(receive_sign_in_payload(world, EVENT_TOPIC, "data", &event_type, &[("login_method", &method)]).await);
}

#[then(expr = "the integration receives a {string} event with login method {string} and failure reason {string}")]
async fn stream_receives_failed_sign_in(
    world: &mut SurfaceWorld,
    event_type: String,
    method: String,
    reason: String,
) {
    let data = [("login_method", method.as_str()), ("failure_reason", reason.as_str())];
    world.sign_in_event = Some(receive_sign_in_payload(world, EVENT_TOPIC, "data", &event_type, &data).await);
}

#[then(
    expr = "that integration receives the {string} event as a record with login method {string} and failure reason {string}"
)]
async fn stream_receives_failed_sign_in_record(
    world: &mut SurfaceWorld,
    event_type: String,
    method: String,
    reason: String,
) {
    let data = [("login_method", method.as_str()), ("failure_reason", reason.as_str())];
    world.sign_in_record = Some(receive_sign_in_payload(world, RECORD_TOPIC, "record", &event_type, &data).await);
}

fn sign_in_event(world: &SurfaceWorld) -> &Value {
    world
        .sign_in_event
        .as_ref()
        .expect("a sign-in event found on the stream")
}

/// Asserts the envelope fields every streamed payload carries: an RFC 3339 `timestamp` and the
/// gateway's Appliance ID.
fn assert_envelope_values(payload: &Value) {
    let timestamp = payload["timestamp"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a timestamp; the payload is {payload}"));
    assert!(
        chrono::DateTime::parse_from_rfc3339(timestamp).is_ok(),
        "expected an RFC 3339 timestamp; it is {timestamp:?}"
    );
    assert_eq!(payload["appliance_id"], APPLIANCE_ID, "expected the Appliance ID; the payload is {payload}");
}

/// Asserts that `event` holds exactly the envelope and event data fields of a sign-in event,
/// naming an account or not.
fn assert_exact_fields(
    event: &Value,
    names_an_account: bool,
) {
    assert_eq!(keys(event), names(&ENVELOPE_FIELDS), "envelope fields of {event}");
    assert_envelope_values(event);
    let data = &event["data"];
    let mut expected = if names_an_account {
        names(&ACCOUNT_DATA_FIELDS)
    } else {
        names(&NO_ACCOUNT_DATA_FIELDS)
    };
    match event["event_type"].as_str() {
        Some("user.login") => assert_eq!(event["event_name"], "User Login", "{event}"),
        Some("user.login_failed") => {
            assert_eq!(event["event_name"], "User Login Failed", "{event}");
            expected.insert("failure_reason".to_string());
        }
        other => panic!("expected a sign-in event; its type is {other:?}"),
    }
    assert_eq!(keys(data), expected, "event data fields of {event}");
    assert_eq!(data["old_state"], Value::Null, "{event}");
    if names_an_account {
        assert_eq!(keys(&data["new_state"]), names(&STATE_FIELDS), "new_state fields of {event}");
    } else {
        assert_eq!(data["new_state"], Value::Null, "{event}");
    }
}

#[then("that event carries only the fields of a sign-in event for an existing account")]
fn event_has_the_fields_naming_an_account(world: &mut SurfaceWorld) {
    assert_exact_fields(sign_in_event(world), true);
}

#[then("that event carries only the fields of a sign-in event for no account")]
fn event_has_the_fields_naming_no_account(world: &mut SurfaceWorld) {
    assert_exact_fields(sign_in_event(world), false);
}

#[then(expr = "that event names human user {string}")]
async fn event_names_console_user(
    world: &mut SurfaceWorld,
    username: String,
) {
    let stored = console_user(world, &username).await;
    let data = &sign_in_event(world)["data"];
    let state = &data["new_state"];
    for (field, value) in [
        ("user_id", &stored["user_id"]),
        ("username", &stored["username"]),
        (
            "user_email",
            &json!(
                stored["email"]
                    .as_str()
                    .unwrap_or_default()
            ),
        ),
        ("user_role", &stored["role"]),
        ("user_status", &stored["status"]),
    ] {
        assert_eq!(&data[field], value, "{field}: expected {username}'s stored {value}; the event data is {data}");
    }
    for field in ["user_id", "role", "status", "is_primary", "created_at"] {
        assert_eq!(state[field], stored[field], "new_state {field}: expected {username}'s stored account {stored}");
    }
    let updated_at = state["updated_at"]
        .as_str()
        .unwrap_or_default();
    assert!(chrono::DateTime::parse_from_rfc3339(updated_at).is_ok(), "new_state updated_at {updated_at:?}");
}

#[then("that event names no failure reason")]
fn event_names_no_failure_reason(world: &mut SurfaceWorld) {
    let data = &sign_in_event(world)["data"];
    assert!(
        data.get("failure_reason")
            .is_none(),
        "expected no failure_reason; the event data is {data}"
    );
}

#[then(expr = "that event matches the reference event {string}")]
fn event_matches_golden(
    world: &mut SurfaceWorld,
    name: String,
) {
    let event = sign_in_event(world);
    if updates_golden() {
        write_golden(&name, event);
    }
    assert_eq!(normalise(event), golden(&name), "the event {event} against {}", golden_path(&name).display());
}

#[then(expr = "that record matches the reference event {string}")]
fn record_matches_golden(
    world: &mut SurfaceWorld,
    name: String,
) {
    let record = world
        .sign_in_record
        .as_ref()
        .expect("a sign-in record found on the stream");
    assert_eq!(keys(record), names(&RECORD_FIELDS), "record fields of {record}");
    assert_envelope_values(record);
    let golden = golden(&name);
    let normalised = normalise(record);
    for field in ["event_type", "timestamp", "appliance_id"] {
        assert_eq!(normalised[field], golden[field], "{field} of {record} against {name}");
    }
    assert_eq!(normalised["record"], golden["data"], "the record of {record} against the data of {name}");
}

#[then("the integration receives no other sign-in event")]
async fn event_is_the_only_one(world: &mut SurfaceWorld) {
    tokio::time::sleep(EXACTLY_ONCE_WAIT).await;
    let received = payloads(world, EVENT_TOPIC);
    assert_eq!(received.len(), 1, "expected one sign-in event; the stream received {received:?}");
}

#[then("the integration receives no sign-in event")]
async fn stream_receives_no_sign_in_event(world: &mut SurfaceWorld) {
    tokio::time::sleep(NO_EVENT_WAIT).await;
    let received = world
        .sign_in_stream
        .as_ref()
        .expect("the stream")
        .entries();
    assert!(received.is_empty(), "expected no sign-in event; the stream received {received:?}");
}

#[then(expr = "that event does not contain {string}")]
fn event_does_not_contain(
    world: &mut SurfaceWorld,
    text: String,
) {
    let event = sign_in_event(world).to_string();
    assert!(!event.contains(&text), "expected the event not to contain {text:?}; it is {event}");
}
