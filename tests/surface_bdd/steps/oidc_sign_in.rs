use cucumber::{given, then, when};
use serde_json::{Value, json};

use crate::bdd_support::admin_client::RecordedResponse;
use crate::bdd_support::config::sign_in::post_logout_redirect_uri;
use crate::bdd_support::dashboard_op::{BOUND_TENANT, DASHBOARD_CLIENT_ID, DashboardOp};
use crate::steps::sign_in_events::stored_users;
use crate::steps::when::ensure_gateway_running;
use crate::world::SurfaceWorld;

/// The session cookie the gateway sets on a completed sign-in.
const SESSION_COOKIE: &str = "__Host-session_token=";

fn gateway_port(world: &SurfaceWorld) -> u16 {
    world
        .infra
        .as_ref()
        .expect("the gateway runs")
        .gateway_port
}

fn gateway_url(
    world: &SurfaceWorld,
    path: &str,
) -> String {
    format!("http://127.0.0.1:{}{path}", gateway_port(world))
}

fn provider(world: &SurfaceWorld) -> &DashboardOp {
    world
        .dashboard_op
        .as_ref()
        .expect("the OpenID provider runs")
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

/// Start a sign-in at the gateway's `/api/oidc/login` and follow it through the provider, which
/// signs in whoever the scenario set.
async fn approve_sign_in(world: &SurfaceWorld) -> ApprovedSignIn {
    approve_sign_in_from(world, "/api/oidc/login").await
}

/// Start a sign-in at the gateway's `start` address and follow it through the provider.
async fn approve_sign_in_from(
    world: &SurfaceWorld,
    start: &str,
) -> ApprovedSignIn {
    let browser = browser();
    let started = browser
        .get(gateway_url(world, start))
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
    sign_in_with(world, person, tenant, roles, json!({}), "/api/oidc/login").await;
}

/// `person` signs in at the provider as a member of `tenant` with the role values `roles` and the
/// further ID token claims `extra`, starting at the gateway's `start` address.
async fn sign_in_with(
    world: &mut SurfaceWorld,
    person: &str,
    tenant: &str,
    roles: &str,
    extra: Value,
    start: &str,
) {
    ensure_gateway_running(world).await;
    let roles: Vec<&str> = roles
        .split(',')
        .map(str::trim)
        .filter(|role| !role.is_empty())
        .collect();
    let mut claims = json!({ "org_id": tenant, "roles": roles, "email": format!("{person}@example.test") });
    for (name, value) in extra
        .as_object()
        .expect("claims are an object")
    {
        claims[name] = value.clone();
    }
    provider(world)
        .sign_in_as(person, claims)
        .await;
    let approved = approve_sign_in_from(world, start).await;
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

/// The key the session `person` was handed in the provider session `sid` is kept under, beside
/// the one under `person`, which names their latest session.
fn provider_session_key(
    person: &str,
    sid: &str,
) -> String {
    format!("{person} in {sid}")
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

/// `key` is a top-level `oidc.json` field, or `block.field` for a field of a block such as
/// `logout`, which then replaces the fixture's block.
#[given(regex = r#"^oidc\.json sets "([^"]+)" to (true|false|"[^"]*")$"#)]
fn oidc_json_sets(
    world: &mut SurfaceWorld,
    key: String,
    value: String,
) {
    let value: Value =
        serde_json::from_str(&value).unwrap_or_else(|error| panic!("the oidc.json value {value} is JSON: {error}"));
    let settings = &mut world
        .surface_config
        .oidc_settings;
    match key.split_once('.') {
        Some((block, field)) => {
            settings
                .entry(block)
                .or_insert_with(|| json!({}))[field] = value;
        }
        None => {
            settings.insert(key, value);
        }
    }
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
    for path in [
        "/api/oidc/login",
        "/api/oidc/callback?code=c&state=s",
        "/api/oidc/initiate?iss=https%3A%2F%2Fidp.example.test",
        "/api/oidc/backchannel-logout",
        "/api/oidc/logout",
    ] {
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
    world.caller_response = Some(RecordedResponse {
        status: response.status().as_u16(),
        headers: Default::default(),
        body: response
            .json()
            .await
            .expect("a JSON answer"),
    });
}

#[then(
    expr = "the sign-out sends the browser to the provider, naming the sign-in of {string} in the provider session {string}"
)]
fn sign_out_sends_the_browser_to_the_provider(
    world: &mut SurfaceWorld,
    person: String,
    sid: String,
) {
    let answer = recorded(world);
    let address = answer.body["end_session_url"]
        .as_str()
        .unwrap_or_else(|| panic!("no end_session_url: {answer:?}"));
    let address = url::Url::parse(address).expect("an absolute sign-out address");
    assert!(
        address
            .as_str()
            .starts_with(&format!("{}?", provider(world).end_session_endpoint())),
        "{address}"
    );
    let query: std::collections::HashMap<String, String> = address
        .query_pairs()
        .into_owned()
        .collect();
    assert_eq!(
        query
            .get("client_id")
            .map(String::as_str),
        Some(DASHBOARD_CLIENT_ID),
        "{address}"
    );
    assert_eq!(
        query.get("post_logout_redirect_uri"),
        Some(&post_logout_redirect_uri(gateway_port(world))),
        "{address}"
    );
    assert!(
        query
            .get("state")
            .is_some_and(|state| !state.is_empty()),
        "{address}"
    );
    let hint = query
        .get("id_token_hint")
        .unwrap_or_else(|| panic!("no id_token_hint: {address}"));
    let header = jsonwebtoken::decode_header(hint).expect("the hint is a JWT");
    assert_eq!(header.typ.as_deref(), Some("JWT"), "the hint is the ID token the sign-in used");
    let claims = jsonwebtoken::dangerous::insecure_decode::<Value>(hint)
        .expect("the hint's claims")
        .claims;
    assert_eq!(claims["sub"], person.as_str(), "{claims}");
    assert_eq!(claims["sid"], sid.as_str(), "{claims}");
}

#[then("the sign-out leaves the browser in the dashboard")]
fn sign_out_leaves_the_browser_in_the_dashboard(world: &mut SurfaceWorld) {
    let answer = recorded(world);
    assert_eq!(answer.body, json!({}), "{answer:?}");
}

#[given(
    expr = "{string} has signed in with OpenID Connect in the provider session {string} carrying the roles {string}"
)]
async fn has_signed_in_in_provider_session(
    world: &mut SurfaceWorld,
    person: String,
    sid: String,
    roles: String,
) {
    sign_in_with(world, &person, BOUND_TENANT, &roles, json!({ "sid": sid }), "/api/oidc/login").await;
    assert_eq!(recorded(world).status, 200, "the earlier sign-in succeeds: {:?}", world.caller_response);
    let session = session_of(world, &person);
    world
        .oidc_sessions
        .insert(provider_session_key(&person, &sid), session);
}

/// The provider posts `logout_token` to the gateway's back-channel logout address, server to
/// server, and the gateway's answer is recorded.
async fn post_logout_token(
    world: &mut SurfaceWorld,
    logout_token: &str,
) {
    ensure_gateway_running(world).await;
    let response = browser()
        .post(gateway_url(world, "/api/oidc/backchannel-logout"))
        .form(&[("logout_token", logout_token)])
        .send()
        .await
        .expect("the back-channel logout");
    let status = response.status().as_u16();
    let cache_control = response
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = response
        .text()
        .await
        .expect("the answer");
    world.caller_response = Some(RecordedResponse {
        status,
        headers: cache_control
            .map(|value| [("cache-control".to_string(), value)].into())
            .unwrap_or_default(),
        body: serde_json::from_str(&body).unwrap_or(Value::String(body)),
    });
}

#[when(expr = "the provider signs {string} out of the provider session {string}")]
async fn provider_signs_out_of_session(
    world: &mut SurfaceWorld,
    person: String,
    sid: String,
) {
    let token = provider(world).logout_token(&person, Some(&sid));
    post_logout_token(world, &token).await;
}

#[given(expr = "the provider has signed {string} out of the provider session {string}")]
async fn provider_has_signed_out_of_session(
    world: &mut SurfaceWorld,
    person: String,
    sid: String,
) {
    provider_signs_out_of_session(world, person, sid).await;
    assert_eq!(recorded(world).status, 200, "the earlier logout succeeds: {:?}", world.caller_response);
}

#[when(expr = "the provider signs {string} out of every provider session")]
async fn provider_signs_out_of_every_session(
    world: &mut SurfaceWorld,
    person: String,
) {
    let token = provider(world).logout_token(&person, None);
    post_logout_token(world, &token).await;
}

#[when("the provider sends its last logout token again")]
async fn provider_sends_last_logout_token_again(world: &mut SurfaceWorld) {
    let token = provider(world).last_logout_token();
    post_logout_token(world, &token).await;
}

#[when(expr = "the provider signs {string} out of the provider session {string} with a key it never published")]
async fn provider_signs_out_with_unpublished_key(
    world: &mut SurfaceWorld,
    person: String,
    sid: String,
) {
    let token = provider(world).logout_token_signed_with_an_unpublished_key(&person, &sid);
    post_logout_token(world, &token).await;
}

#[when(expr = "the provider posts an ID token for {string} as a logout token")]
async fn provider_posts_an_id_token_as_a_logout_token(
    world: &mut SurfaceWorld,
    person: String,
) {
    let token = provider(world).id_token(&person);
    post_logout_token(world, &token).await;
}

#[then(expr = "the back-channel logout is refused as {string}")]
fn back_channel_logout_is_refused_as(
    world: &mut SurfaceWorld,
    error: String,
) {
    let answer = recorded(world);
    assert_eq!(answer.status, 400, "{answer:?}");
    assert_eq!(answer.body, json!({ "error": error }), "{answer:?}");
    assert_eq!(
        answer
            .headers
            .get("cache-control")
            .map(String::as_str),
        Some("no-store"),
        "{answer:?}"
    );
}

/// The query of a sign-in link the provider gives out: its issuer and `extra` parameters.
fn sign_in_link_query(
    issuer: &str,
    extra: &[(&str, &str)],
) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("iss", issuer)
        .extend_pairs(extra)
        .finish()
}

/// Record the gateway's answer to a sign-in link, keeping where it sends the browser.
async fn record_sign_in_link_answer(
    world: &mut SurfaceWorld,
    response: reqwest::Response,
) {
    let status = response.status().as_u16();
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = response
        .text()
        .await
        .expect("the answer");
    world.caller_response = Some(RecordedResponse {
        status,
        headers: location
            .map(|value| [("location".to_string(), value)].into())
            .unwrap_or_default(),
        body: Value::String(body),
    });
}

#[when(expr = "a browser follows the provider's sign-in link with the login hint {string}")]
async fn browser_follows_sign_in_link(
    world: &mut SurfaceWorld,
    hint: String,
) {
    ensure_gateway_running(world).await;
    let issuer = provider(world)
        .issuer()
        .to_string();
    let query = sign_in_link_query(&issuer, &[("login_hint", &hint)]);
    let response = browser()
        .get(gateway_url(world, &format!("/api/oidc/initiate?{query}")))
        .send()
        .await
        .expect("the sign-in link");
    record_sign_in_link_answer(world, response).await;
}

#[when(expr = "the provider's page posts its sign-in link with the login hint {string}")]
async fn provider_page_posts_sign_in_link(
    world: &mut SurfaceWorld,
    hint: String,
) {
    ensure_gateway_running(world).await;
    let issuer = provider(world)
        .issuer()
        .to_string();
    let response = browser()
        .post(gateway_url(world, "/api/oidc/initiate"))
        .header(reqwest::header::ORIGIN, &issuer)
        .header("sec-fetch-site", "cross-site")
        .form(&[("iss", issuer.as_str()), ("login_hint", hint.as_str())])
        .send()
        .await
        .expect("the sign-in link");
    record_sign_in_link_answer(world, response).await;
}

#[given(expr = "a browser has followed the provider's sign-in link {int} times")]
async fn browser_has_followed_sign_in_link(
    world: &mut SurfaceWorld,
    times: u32,
) {
    ensure_gateway_running(world).await;
    let query = sign_in_link_query(provider(world).issuer(), &[]);
    for attempt in 1..=times {
        let response = browser()
            .get(gateway_url(world, &format!("/api/oidc/initiate?{query}")))
            .send()
            .await
            .expect("the sign-in link");
        assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER, "link {attempt} starts a sign-in");
    }
}

#[when("the browser starts a sign-in from the login button")]
async fn browser_starts_sign_in_from_login_button(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let response = browser()
        .get(gateway_url(world, "/api/oidc/login"))
        .send()
        .await
        .expect("the login button's sign-in");
    record_sign_in_link_answer(world, response).await;
}

#[when("a browser follows a sign-in link that names another provider")]
async fn browser_follows_link_for_another_provider(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let query = sign_in_link_query("https://idp.other.example", &[("login_hint", "mallory@example.test")]);
    let response = browser()
        .get(gateway_url(world, &format!("/api/oidc/initiate?{query}")))
        .send()
        .await
        .expect("the sign-in link");
    record_sign_in_link_answer(world, response).await;
}

#[then(expr = "the browser is sent to the provider with the login hint {string}")]
fn browser_is_sent_to_provider_with_login_hint(
    world: &mut SurfaceWorld,
    hint: String,
) {
    let answer = recorded(world);
    assert_eq!(answer.status, 303, "{answer:?}");
    let location = answer
        .headers
        .get("location")
        .unwrap_or_else(|| panic!("no redirect: {answer:?}"));
    let location = url::Url::parse(location).expect("an absolute address");
    assert!(
        location
            .as_str()
            .starts_with(&format!("{}/authorize?", provider(world).issuer())),
        "{location}"
    );
    let login_hint = location
        .query_pairs()
        .find(|(name, _)| name == "login_hint")
        .map(|(_, value)| value.into_owned());
    assert_eq!(login_hint.as_deref(), Some(hint.as_str()), "{location}");
}

/// `person` signs in from the provider's sign-in link with `target_link_uri` set to `target`.
async fn sign_in_from_link(
    world: &mut SurfaceWorld,
    person: &str,
    target: &str,
    roles: &str,
) {
    ensure_gateway_running(world).await;
    let issuer = provider(world)
        .issuer()
        .to_string();
    let query = sign_in_link_query(&issuer, &[("target_link_uri", target)]);
    sign_in_with(world, person, BOUND_TENANT, roles, json!({}), &format!("/api/oidc/initiate?{query}")).await;
}

#[when(
    expr = "{string} signs in from the provider's link opening the dashboard page {string} carrying the roles {string}"
)]
async fn signs_in_from_link_to_dashboard_page(
    world: &mut SurfaceWorld,
    person: String,
    path: String,
    roles: String,
) {
    ensure_gateway_running(world).await;
    let target = format!("http://localhost:{}{path}", gateway_port(world));
    sign_in_from_link(world, &person, &target, &roles).await;
}

#[when(expr = "{string} signs in from the provider's link opening {string} carrying the roles {string}")]
async fn signs_in_from_link_to(
    world: &mut SurfaceWorld,
    person: String,
    target: String,
    roles: String,
) {
    sign_in_from_link(world, &person, &target, &roles).await;
}

#[then(expr = "the dashboard opens at {string}")]
fn dashboard_opens_at(
    world: &mut SurfaceWorld,
    expected: String,
) {
    let answer = recorded(world);
    assert_eq!(answer.status, 200, "{answer:?}");
    let page = answer
        .body
        .as_str()
        .unwrap_or_default();
    let literal = page
        .split("window.location.href = ")
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .unwrap_or_else(|| panic!("the hand-off page sends the browser nowhere: {page}"));
    let target: String = serde_json::from_str(literal).expect("a JSON string literal");
    assert_eq!(target, expected, "{page}");
}

#[then(expr = "the session {string} was handed is refused")]
async fn handed_session_is_refused(
    world: &mut SurfaceWorld,
    person: String,
) {
    session_is_refused(world, &session_of(world, &person)).await;
}

#[then(expr = "the session {string} was handed in the provider session {string} is refused")]
async fn handed_provider_session_is_refused(
    world: &mut SurfaceWorld,
    person: String,
    sid: String,
) {
    session_is_refused(world, &session_of(world, &provider_session_key(&person, &sid))).await;
}

async fn session_is_refused(
    world: &SurfaceWorld,
    session: &str,
) {
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
    session_signs_in_with_role(world, &person, &session_of(world, &person), &role).await;
}

#[then(expr = "the session {string} was handed in the provider session {string} signs them in with the role {string}")]
async fn handed_provider_session_signs_in_with_role(
    world: &mut SurfaceWorld,
    person: String,
    sid: String,
    role: String,
) {
    let session = session_of(world, &provider_session_key(&person, &sid));
    session_signs_in_with_role(world, &person, &session, &role).await;
}

async fn session_signs_in_with_role(
    world: &SurfaceWorld,
    person: &str,
    session: &str,
    role: &str,
) {
    let check: Value = browser()
        .get(gateway_url(world, "/api/auth/check"))
        .bearer_auth(session)
        .send()
        .await
        .expect("the session check")
        .json()
        .await
        .expect("a JSON answer");
    assert_eq!(check["authenticated"], true, "{check}");
    assert_eq!(check["username"], person, "{check}");
    let profile: Value = browser()
        .get(gateway_url(world, "/api/v1/profile"))
        .bearer_auth(session)
        .send()
        .await
        .expect("the profile")
        .json()
        .await
        .expect("a JSON profile");
    assert_eq!(profile["role"], role, "{profile}");
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
