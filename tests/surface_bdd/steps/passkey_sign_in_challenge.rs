use base64::Engine;
use cucumber::{then, when};
use reqwest::Method;
use serde_json::{Value, json};

use crate::bdd_support::admin_client::recorded_response;
use crate::bdd_support::passkey::SoftPasskey;
use crate::steps::sign_in_events::{finish_sign_in, passkey_for, post_json, start_passkey_sign_in};
use crate::steps::when::ensure_admin_session;
use crate::world::SurfaceWorld;

/// Decoy credential ID lengths: platform passkeys, UUID IDs, Windows Hello, security keys.
const DECOY_ID_LENGTHS: [usize; 4] = [16, 20, 32, 64];

#[when(expr = "passkey sign-ins are started twice for {string}")]
async fn passkey_sign_ins_started_twice(
    world: &mut SurfaceWorld,
    username: String,
) {
    start_passkey_sign_in(world, username.clone()).await;
    start_passkey_sign_in(world, username).await;
}

#[when(expr = "a passkey sign-in is started for {string}")]
async fn passkey_sign_in_started_for(
    world: &mut SurfaceWorld,
    username: String,
) {
    start_passkey_sign_in(world, username).await;
}

fn credential_ids(credentials: &[Value]) -> Vec<String> {
    credentials
        .iter()
        .map(|credential| {
            credential["id"]
                .as_str()
                .unwrap_or_else(|| panic!("a credential without an id: {credential}"))
                .to_string()
        })
        .collect()
}

#[then("both sign-in challenges name the same decoy credentials")]
fn both_challenges_name_the_same_decoys(world: &mut SurfaceWorld) {
    let [first, second] = world
        .sign_in_challenge_credentials
        .as_slice()
    else {
        panic!("two sign-in challenges: {:?}", world.sign_in_challenge_credentials);
    };
    assert_eq!(credential_ids(first), credential_ids(second));
    assert!((1..=3).contains(&first.len()), "{first:?}");
    for credential in first {
        let id = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(
                credential["id"]
                    .as_str()
                    .expect("a credential id"),
            )
            .expect("a base64url credential id");
        assert!(DECOY_ID_LENGTHS.contains(&id.len()), "{credential}");
        assert_eq!(credential["type"], "public-key", "{credential}");
        assert!(
            credential
                .get("transports")
                .is_none(),
            "{credential}"
        );
    }
}

#[then(expr = "the sign-in challenge names only the passkey of human user {string}")]
fn challenge_names_only_users_passkey(
    world: &mut SurfaceWorld,
    username: String,
) {
    let passkey = world
        .passkeys
        .get(&username)
        .unwrap_or_else(|| panic!("{username} registered no passkey"));
    let named = world
        .sign_in_challenge_credentials
        .last()
        .expect("a sign-in challenge");
    assert_eq!(credential_ids(named), vec![passkey.credential_id()]);
}

#[then(expr = "the sign-in challenge does not name the passkey of human user {string}")]
fn challenge_does_not_name_users_passkey(
    world: &mut SurfaceWorld,
    username: String,
) {
    let passkey = world
        .passkeys
        .get(&username)
        .unwrap_or_else(|| panic!("{username} registered no passkey"));
    for named in &world.sign_in_challenge_credentials {
        assert!(!credential_ids(named).contains(&passkey.credential_id()), "{named:?}");
    }
}

#[when(expr = "another passkey is registered for the username {string}")]
async fn another_passkey_registers_username(
    world: &mut SurfaceWorld,
    username: String,
) {
    let passkey = register_timed(world, username).await;
    world.other_passkey = Some(passkey);
}

#[when(expr = "a passkey is registered for the new username {string}")]
async fn passkey_registers_new_username(
    world: &mut SurfaceWorld,
    username: String,
) {
    ensure_admin_session(world).await;
    register_timed(world, username).await;
}

#[then(expr = "the registration was answered no sooner than {int} ms")]
fn registration_answered_no_sooner_than(
    world: &mut SurfaceWorld,
    millis: u64,
) {
    let answered = world
        .registration_answer_time
        .expect("a finished registration");
    assert!(answered >= std::time::Duration::from_millis(millis), "answered after {answered:?}");
}

/// Registers a passkey for `username`, records the response and how long the finish took to be
/// answered, and returns the passkey.
async fn register_timed(
    world: &mut SurfaceWorld,
    username: String,
) -> SoftPasskey {
    let passkey = passkey_for(world);
    let started: Value = post_json(world, "/auth/register/start", &json!({"username": username}))
        .await
        .json()
        .await
        .expect("a registration challenge");
    let credential = passkey.register(&started["creation_options"]);
    let sent = std::time::Instant::now();
    let finished = post_json(
        world,
        "/auth/register/finish",
        &json!({"challenge_id": started["challenge_id"], "credential": credential}),
    )
    .await;
    world.registration_answer_time = Some(sent.elapsed());
    world.caller_response = Some(
        recorded_response(finished)
            .await
            .expect("record the registration response"),
    );
    passkey
}

#[then(expr = "human user {string} is listed once, with status {string}")]
async fn console_user_listed_once(
    world: &mut SurfaceWorld,
    username: String,
    status: String,
) {
    ensure_admin_session(world).await;
    let users: Vec<Value> = world
        .admin_client
        .as_ref()
        .expect("admin session")
        .send_json::<(), _>(Method::GET, "/v1/users", None)
        .await
        .expect("list the console users");
    let listed: Vec<&Value> = users
        .iter()
        .filter(|user| user["username"] == username)
        .collect();
    assert_eq!(listed.len(), 1, "{users:?}");
    assert_eq!(listed[0]["status"], status, "{users:?}");
}

#[then(expr = "human user {string} still signs in with the passkey they registered")]
async fn console_user_still_signs_in(
    world: &mut SurfaceWorld,
    username: String,
) {
    start_passkey_sign_in(world, username.clone()).await;
    let started = world
        .started_sign_in
        .as_ref()
        .expect("a started sign-in");
    let credential = world
        .passkeys
        .get_mut(&username)
        .unwrap_or_else(|| panic!("{username} registered no passkey"))
        .sign_in(&started.request_options);
    finish_sign_in(world, credential).await;
    let response = world
        .caller_response
        .as_ref()
        .expect("a sign-in response");
    assert_eq!(response.status, 200, "{response:?}");
}

#[then(expr = "the other passkey cannot sign in as human user {string}")]
async fn other_passkey_cannot_sign_in(
    world: &mut SurfaceWorld,
    username: String,
) {
    start_passkey_sign_in(world, username).await;
    let started = world
        .started_sign_in
        .as_ref()
        .expect("a started sign-in");
    let credential = world
        .other_passkey
        .as_mut()
        .expect("another passkey was registered")
        .sign_in(&started.request_options);
    finish_sign_in(world, credential).await;
    let response = world
        .caller_response
        .as_ref()
        .expect("a sign-in response");
    assert_eq!(response.status, 401, "{response:?}");
}
