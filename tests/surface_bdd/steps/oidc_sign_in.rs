use cucumber::{given, then, when};
use serde_json::{Value, json};

use crate::bdd_support::admin_client::RecordedResponse;
use crate::bdd_support::dashboard_op::{BOUND_TENANT, DashboardOp};
use crate::steps::sign_in_events::stored_users;
use crate::steps::when::ensure_gateway_running;
use crate::world::SurfaceWorld;

/// The session cookie the gateway sets on a completed sign-in.
const SESSION_COOKIE: &str = "__Host-session_token=";

fn gateway_url(
    world: &SurfaceWorld,
    path: &str,
) -> String {
    let port = world
        .infra
        .as_ref()
        .expect("the gateway runs")
        .gateway_port;
    format!("http://127.0.0.1:{port}{path}")
}

fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("a browser stand-in")
}

fn location(response: &reqwest::Response) -> String {
    response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("a redirect, got {} {:?}", response.status(), response.headers()))
        .to_string()
}

/// A sign-in started at the gateway and approved at the provider: the binding cookie the browser
/// was given and the callback address the provider sent it back to.
struct ApprovedSignIn {
    binding_cookie: String,
    callback: String,
}

/// Start a sign-in at the gateway and follow it through the provider, which signs in whoever the
/// scenario set.
async fn approve_sign_in(world: &SurfaceWorld) -> ApprovedSignIn {
    let browser = browser();
    let started = browser
        .get(gateway_url(world, "/api/oidc/login"))
        .send()
        .await
        .expect("start the sign-in");
    assert_eq!(started.status(), reqwest::StatusCode::SEE_OTHER, "the gateway sends the browser to the provider");
    let binding_cookie = started
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookie| cookie.split(';').next())
        .expect("the sign-in's binding cookie")
        .to_string();
    let authorization = location(&started);
    let approved = browser
        .get(&authorization)
        .send()
        .await
        .expect("the provider's authorization endpoint");
    assert_eq!(approved.status(), reqwest::StatusCode::FOUND, "the provider signs the person in");
    ApprovedSignIn {
        binding_cookie,
        callback: location(&approved),
    }
}

/// Open the provider's callback address, with `cookie` when the browser holds one, and record the
/// gateway's answer, and the session it hands `person` when it signs them in.
async fn open_callback(
    world: &mut SurfaceWorld,
    person: &str,
    callback: &str,
    cookie: Option<&str>,
) {
    let mut request = browser().get(callback);
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    let response = request
        .send()
        .await
        .expect("the gateway's callback");
    let status = response.status().as_u16();
    let set_cookies: Vec<String> = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_string)
        .collect();
    let body = response
        .text()
        .await
        .expect("the callback's page");
    if let Some(session) = handed_off_session(&body) {
        world
            .oidc_sessions
            .insert(person.to_string(), session);
    }
    world.caller_response = Some(RecordedResponse {
        status,
        headers: if set_cookies.is_empty() {
            Default::default()
        } else {
            [("set-cookie".to_string(), set_cookies.join("\n"))].into()
        },
        body: Value::String(body),
    });
}

/// `person` signs in at the provider as a member of `tenant` with the role values `roles`.
async fn sign_in(
    world: &mut SurfaceWorld,
    person: &str,
    tenant: &str,
    roles: &str,
) {
    ensure_gateway_running(world).await;
    let roles: Vec<&str> = roles
        .split(',')
        .map(str::trim)
        .filter(|role| !role.is_empty())
        .collect();
    world
        .dashboard_op
        .as_ref()
        .expect("the OpenID provider runs")
        .sign_in_as(person, json!({ "org_id": tenant, "roles": roles, "email": format!("{person}@example.test") }))
        .await;
    let approved = approve_sign_in(world).await;
    open_callback(world, person, &approved.callback, Some(&approved.binding_cookie)).await;
}

/// The session token the hand-off page stores for the dashboard, when it stores one.
fn handed_off_session(page: &str) -> Option<String> {
    let literal = page
        .split("sessionStorage.setItem('session_token', ")
        .nth(1)?
        .split(')')
        .next()?;
    serde_json::from_str(literal).ok()
}

fn session_of(
    world: &SurfaceWorld,
    person: &str,
) -> String {
    world
        .oidc_sessions
        .get(person)
        .cloned()
        .unwrap_or_else(|| panic!("{person} was handed no session"))
}

fn recorded(world: &SurfaceWorld) -> &RecordedResponse {
    world
        .caller_response
        .as_ref()
        .expect("the gateway answered the sign-in")
}

#[given("human users sign in with OpenID Connect")]
async fn human_users_sign_in_with_oidc(world: &mut SurfaceWorld) {
    let provider = DashboardOp::start().await;
    world
        .surface_config
        .signs_in_with_oidc = Some(provider.issuer().to_string());
    world.dashboard_op = Some(provider);
}

#[given(regex = r#"^oidc\.json sets "([^"]+)" to (true|false|"[^"]*")$"#)]
fn oidc_json_sets(
    world: &mut SurfaceWorld,
    key: String,
    value: String,
) {
    let value: Value =
        serde_json::from_str(&value).unwrap_or_else(|error| panic!("the oidc.json value {value} is JSON: {error}"));
    world
        .surface_config
        .oidc_settings
        .insert(key, value);
}

#[given("oidc.json has no tenant binding")]
fn oidc_json_binds_no_tenant(world: &mut SurfaceWorld) {
    world
        .surface_config
        .oidc_settings
        .insert("required_claims".to_string(), json!({}));
}

#[given(expr = "{string} has signed in with OpenID Connect carrying the roles {string}")]
async fn has_signed_in_with_oidc(
    world: &mut SurfaceWorld,
    person: String,
    roles: String,
) {
    sign_in(world, &person, BOUND_TENANT, &roles).await;
    assert_eq!(recorded(world).status, 200, "the earlier sign-in succeeds: {:?}", world.caller_response);
}

#[when(expr = "{string} signs in with OpenID Connect carrying the roles {string}")]
async fn signs_in_with_oidc(
    world: &mut SurfaceWorld,
    person: String,
    roles: String,
) {
    sign_in(world, &person, BOUND_TENANT, &roles).await;
}

#[when(expr = "{string} signs in with OpenID Connect from the organisation {string} carrying the roles {string}")]
async fn signs_in_with_oidc_from_organisation(
    world: &mut SurfaceWorld,
    person: String,
    organisation: String,
    roles: String,
) {
    sign_in(world, &person, &organisation, &roles).await;
}

#[given(expr = "the appliance allows {int} human user(s)")]
fn appliance_allows_human_users(
    world: &mut SurfaceWorld,
    limit: u64,
) {
    world
        .surface_config
        .human_user_limit = Some(limit);
}

#[when("a browser opens the OpenID Connect sign-in routes")]
async fn browser_opens_oidc_routes(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let mut answers = Vec::new();
    for path in ["/api/oidc/login", "/api/oidc/callback?code=c&state=s"] {
        let response = browser()
            .get(gateway_url(world, path))
            .send()
            .await
            .expect("the gateway answers");
        answers.push(json!({
            "path": path,
            "status": response.status().as_u16(),
            "location": response.headers().get(reqwest::header::LOCATION).and_then(|value| value.to_str().ok()),
            "set_cookie": response.headers().get(reqwest::header::SET_COOKIE).and_then(|value| value.to_str().ok()),
        }));
    }
    world.caller_response = Some(RecordedResponse {
        status: 0,
        headers: Default::default(),
        body: Value::Array(answers),
    });
}

#[then("the gateway offers no OpenID Connect sign-in")]
fn gateway_offers_no_oidc_sign_in(world: &mut SurfaceWorld) {
    let answers = recorded(world)
        .body
        .as_array()
        .expect("the routes' answers")
        .clone();
    for answer in answers {
        assert_eq!(answer["status"], 404, "{answer}");
        assert!(answer["location"].is_null(), "{answer}");
        assert!(answer["set_cookie"].is_null(), "{answer}");
    }
}

#[when(expr = "{string} signs out of the dashboard")]
async fn signs_out_of_the_dashboard(
    world: &mut SurfaceWorld,
    person: String,
) {
    let session = session_of(world, &person);
    let response = browser()
        .post(gateway_url(world, "/api/auth/logout"))
        .bearer_auth(session)
        .send()
        .await
        .expect("the sign-out");
    assert_eq!(response.status(), reqwest::StatusCode::OK, "signing out");
}

#[then(expr = "the session {string} was handed is refused")]
async fn handed_session_is_refused(
    world: &mut SurfaceWorld,
    person: String,
) {
    let session = session_of(world, &person);
    let response = browser()
        .get(gateway_url(world, "/api/auth/check"))
        .bearer_auth(session)
        .send()
        .await
        .expect("the session check");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[then(expr = "the sign-in page says {string}")]
fn sign_in_page_says(
    world: &mut SurfaceWorld,
    text: String,
) {
    let page = recorded(world)
        .body
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(page.contains(&text), "the page does not say {text:?}: {page}");
}

#[when(expr = "{string} finishes an OpenID Connect sign-in in a browser that did not start it")]
async fn finishes_in_another_browser(
    world: &mut SurfaceWorld,
    person: String,
) {
    ensure_gateway_running(world).await;
    world
        .dashboard_op
        .as_ref()
        .expect("the OpenID provider runs")
        .sign_in_as(&person, json!({ "org_id": BOUND_TENANT, "roles": ["gw-admins"] }))
        .await;
    let approved = approve_sign_in(world).await;
    open_callback(world, &person, &approved.callback, None).await;
}

#[when("the dashboard asks how human users sign in")]
async fn dashboard_asks_sign_in_mode(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let response = browser()
        .get(gateway_url(world, "/api/v1/auth/mode"))
        .send()
        .await
        .expect("the auth mode endpoint");
    world.caller_response = Some(RecordedResponse {
        status: response.status().as_u16(),
        headers: Default::default(),
        body: response
            .json()
            .await
            .expect("a JSON answer"),
    });
}

#[then(expr = "human users sign in with {string} under the label {string}")]
fn sign_in_mode_and_label(
    world: &mut SurfaceWorld,
    mode: String,
    label: String,
) {
    let answer = recorded(world);
    assert_eq!(answer.status, 200, "{answer:?}");
    assert_eq!(answer.body["mode"], mode.as_str(), "{answer:?}");
    assert_eq!(answer.body["label"], label.as_str(), "{answer:?}");
}

#[then("the dashboard is handed a session")]
fn dashboard_is_handed_a_session(world: &mut SurfaceWorld) {
    let answer = recorded(world);
    let cookies = answer
        .headers
        .get("set-cookie")
        .cloned()
        .unwrap_or_default();
    assert!(
        cookies
            .lines()
            .any(|cookie| cookie.starts_with(SESSION_COOKIE) && !cookie.starts_with(&format!("{SESSION_COOKIE};"))),
        "no session cookie was set: {cookies}"
    );
    let page = answer
        .body
        .as_str()
        .unwrap_or_default();
    assert!(page.contains("sessionStorage.setItem('session_token'"), "the page hands no session over: {page}");
}

#[then("the dashboard is handed no session")]
fn dashboard_is_handed_no_session(world: &mut SurfaceWorld) {
    let answer = recorded(world);
    let cookies = answer
        .headers
        .get("set-cookie")
        .cloned()
        .unwrap_or_default();
    assert!(
        !cookies
            .lines()
            .any(|cookie| cookie.starts_with(SESSION_COOKIE)),
        "a session cookie was set: {cookies}"
    );
    let page = answer
        .body
        .as_str()
        .unwrap_or_default();
    assert!(!page.contains("session_token"), "the page hands a session over: {page}");
}

#[then(expr = "the session {string} was handed signs them in with the role {string}")]
async fn handed_session_signs_in_with_role(
    world: &mut SurfaceWorld,
    person: String,
    role: String,
) {
    let session = session_of(world, &person);
    let check: Value = browser()
        .get(gateway_url(world, "/api/auth/check"))
        .bearer_auth(&session)
        .send()
        .await
        .expect("the session check")
        .json()
        .await
        .expect("a JSON answer");
    assert_eq!(check["authenticated"], true, "{check}");
    assert_eq!(check["username"], person.as_str(), "{check}");
    let profile: Value = browser()
        .get(gateway_url(world, "/api/v1/profile"))
        .bearer_auth(&session)
        .send()
        .await
        .expect("the profile")
        .json()
        .await
        .expect("a JSON profile");
    assert_eq!(profile["role"], role.as_str(), "{profile}");
    assert_eq!(profile["status"], "approved", "{profile}");
    assert_eq!(profile["is_primary"], false, "{profile}");
}

#[then(expr = "human user {string} is not stored")]
fn human_user_is_not_stored(
    world: &mut SurfaceWorld,
    username: String,
) {
    let stored = stored_users(world);
    assert!(
        stored
            .iter()
            .all(|user| user["username"] != username.as_str()),
        "{username:?} is stored: {stored:?}"
    );
}

#[then("no human user is stored")]
fn no_human_user_is_stored(world: &mut SurfaceWorld) {
    let stored = stored_users(world);
    assert!(stored.is_empty(), "the refused sign-in stored a user: {stored:?}");
}

/// The stored human users that sign in with `person`'s account at the OpenID provider.
fn stored_users_of_account(
    world: &SurfaceWorld,
    person: &str,
) -> Vec<Value> {
    stored_users(world)
        .into_iter()
        .filter(|user| user["oidc"]["subject"] == person)
        .collect()
}

/// `administrator`, signed in, sends `method` with `body` to the user management route of the one
/// human user that signs in with `person`'s account, and gets the gateway's answer.
async fn manage_human_user(
    world: &SurfaceWorld,
    administrator: &str,
    method: reqwest::Method,
    person: &str,
    body: Option<Value>,
) -> RecordedResponse {
    let users = stored_users_of_account(world, person);
    assert_eq!(users.len(), 1, "{person} has one stored human user: {users:?}");
    let user_id = users[0]["user_id"]
        .as_str()
        .expect("a stored user id");
    let mut request = browser()
        .request(method, gateway_url(world, &format!("/api/v1/users/{user_id}")))
        .bearer_auth(session_of(world, administrator));
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .expect("the user management route");
    let status = response.status().as_u16();
    RecordedResponse {
        status,
        headers: Default::default(),
        body: response
            .json()
            .await
            .unwrap_or(Value::Null),
    }
}

#[when(expr = "{string} deletes human user {string}")]
async fn deletes_human_user(
    world: &mut SurfaceWorld,
    administrator: String,
    person: String,
) {
    let answer = manage_human_user(world, &administrator, reqwest::Method::DELETE, &person, None).await;
    world.caller_response = Some(answer);
}

#[given(expr = "{string} has deleted human user {string}")]
async fn has_deleted_human_user(
    world: &mut SurfaceWorld,
    administrator: String,
    person: String,
) {
    let answer = manage_human_user(world, &administrator, reqwest::Method::DELETE, &person, None).await;
    assert_eq!(answer.status, 200, "the delete succeeds: {answer:?}");
}

#[given(expr = "{string} has approved human user {string} again")]
async fn has_approved_human_user_again(
    world: &mut SurfaceWorld,
    administrator: String,
    person: String,
) {
    let answer =
        manage_human_user(world, &administrator, reqwest::Method::PUT, &person, Some(json!({ "status": "approved" })))
            .await;
    assert_eq!(answer.status, 200, "the approval succeeds: {answer:?}");
}

#[then(expr = "the delete answers the outcome {string}")]
fn delete_answers_outcome(
    world: &mut SurfaceWorld,
    outcome: String,
) {
    let answer = recorded(world);
    assert_eq!(answer.body, json!({ "outcome": outcome }), "{answer:?}");
}

#[then(expr = "the OpenID Connect account {string} has one stored human user, who is {string}")]
fn account_has_one_stored_human_user(
    world: &mut SurfaceWorld,
    person: String,
    status: String,
) {
    let users = stored_users_of_account(world, &person);
    assert_eq!(users.len(), 1, "{person}'s account has one stored human user: {users:?}");
    assert_eq!(users[0]["status"], status.as_str(), "{:?}", users[0]);
}
