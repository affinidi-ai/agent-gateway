use cucumber::{given, then, when};

use crate::bdd_support::oidc::{OIDC_CLIENT_ID, OidcProvider};
use crate::steps::when::{
    caller_invokes_mcp_tool_with_valid_api_key, consent_binding_cookie, ensure_gateway_running, no_redirect_client,
    post_consent_start_page, query_value, record_html_response, record_replacement_mock_observation, redirect_location,
    send_oauth_callback_and_record, valid_code_query,
};
use crate::world::SurfaceWorld;

fn identity_provider(world: &SurfaceWorld) -> &OidcProvider {
    world
        .infra
        .as_ref()
        .and_then(|infra| {
            infra
                .identity_provider
                .as_ref()
        })
        .expect("the callers' identity provider must be running")
}

fn delegated_provider(world: &SurfaceWorld) -> String {
    world
        .surface_config
        .credential_delegation
        .as_ref()
        .map(|delegation| delegation.provider_id.clone())
        .expect("the surface must require delegated credentials from an OAuth provider")
}

/// The OAuth callback URL of the surface's OAuth provider.
fn oauth_callback_url(world: &SurfaceWorld) -> String {
    let base = world
        .surface_config
        .oauth_callback_base_url
        .as_ref()
        .expect("the gateway must be running before its OAuth callback URL is known");
    let segment = world
        .surface_config
        .provider_record_id(&delegated_provider(world));
    format!("{base}/v1/identity/oauth/callback/{segment}")
}

fn recorded_location(
    world: &SurfaceWorld,
    what: &str,
) -> url::Url {
    let response = world
        .caller_response
        .as_ref()
        .expect("a response must be recorded");
    let location = response
        .headers
        .get("location")
        .unwrap_or_else(|| panic!("expected the {what} to send the browser on, got status {}", response.status));
    url::Url::parse(location).expect("the redirect location is a URL")
}

fn without_query(url: &url::Url) -> String {
    let mut endpoint = url.clone();
    endpoint.set_query(None);
    endpoint.to_string()
}

#[given("the callers' identity provider is available")]
fn callers_identity_provider_is_available(world: &mut SurfaceWorld) {
    world
        .surface_config
        .identity_provider = true;
}

#[given(expr = "OAuth provider {string} confirms its caller at the identity provider")]
fn oauth_provider_confirms_its_caller(
    world: &mut SurfaceWorld,
    provider: String,
) {
    assert_eq!(delegated_provider(world), provider, "only the surface's own OAuth provider confirms its caller");
    callers_identity_provider_is_available(world);
    world
        .surface_config
        .consent_confirmation = true;
}

#[given("the identity provider issues ID tokens without the nonce of the sign-in")]
async fn identity_provider_omits_nonce(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    identity_provider(world).omit_nonce();
}

#[given(expr = "caller {string} has started OAuth consent for provider {string} with a valid API key")]
async fn caller_has_started_oauth_consent_with_api_key(
    world: &mut SurfaceWorld,
    _caller: String,
    _provider: String,
) {
    caller_invokes_mcp_tool_with_valid_api_key(world, "schedule_meeting".to_string()).await;
}

#[when(expr = "caller {string} confirms the consent start page for provider {string}")]
async fn caller_confirms_consent_start_page(
    world: &mut SurfaceWorld,
    _caller: String,
    provider: String,
) {
    let started = post_consent_start_page(world, &provider).await;
    record_html_response(world, started).await;
}

/// Confirm the consent start page, sign `person` in at the identity provider and
/// keep where it sends the browser back to, with the binding cookie.
#[given(expr = "caller {string} has signed in at the identity provider as {string}")]
async fn caller_has_signed_in_at_identity_provider(
    world: &mut SurfaceWorld,
    _caller: String,
    person: String,
) {
    let provider = delegated_provider(world);
    let started = post_consent_start_page(world, &provider).await;
    assert_eq!(started.status().as_u16(), 302, "the consent start POST sends the browser to the identity provider");
    let cookie = consent_binding_cookie(started.headers());
    let sign_in = redirect_location(started.headers());
    let identity_provider = identity_provider(world);
    identity_provider
        .sign_in(&person)
        .await;
    let signed_in = no_redirect_client()
        .get(
            identity_provider
                .local_url(&sign_in)
                .expect("the consent start POST sends the browser to the identity provider"),
        )
        .send()
        .await
        .expect("sign in at the identity provider");
    assert_eq!(signed_in.status().as_u16(), 302, "the identity provider sends the browser back to the gateway");
    world.consent_confirmation_callback = Some(redirect_location(signed_in.headers()).to_string());
    world.oauth_binding_cookie = Some(cookie);
}

#[when("the identity provider sends the caller back to the gateway")]
async fn identity_provider_sends_caller_back(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let callback = world
        .consent_confirmation_callback
        .clone()
        .expect("the caller signed in at the identity provider first");
    let mut request = no_redirect_client().get(callback);
    if let Some(cookie) = &world.oauth_binding_cookie {
        request = request.header("cookie", cookie);
    }
    let response = request
        .send()
        .await
        .expect("send the identity provider's answer to the gateway");
    record_html_response(world, response).await;
    record_replacement_mock_observation(world).await;
}

#[given("the identity provider has sent the caller back to the gateway")]
async fn identity_provider_has_sent_caller_back(world: &mut SurfaceWorld) {
    identity_provider_sends_caller_back(world).await;
    let vendor = recorded_location(world, "consent confirmation callback response");
    world.oauth_confirmed_state = Some(query_value(&vendor, "state"));
}

#[given(expr = "OAuth provider {string} has sent the caller back with a valid authorization code")]
async fn oauth_provider_has_sent_caller_back_with_valid_code(
    world: &mut SurfaceWorld,
    provider: String,
) {
    let state = world
        .oauth_confirmed_state
        .clone()
        .expect("the gateway sent the caller to the OAuth provider first");
    let cookie = world
        .oauth_binding_cookie
        .clone();
    send_oauth_callback_and_record(world, &provider, &valid_code_query(&state, &[]), cookie.as_deref()).await;
    let status = world
        .caller_response
        .as_ref()
        .map(|response| response.status);
    assert_eq!(status, Some(200), "the OAuth callback stores the delegated credentials");
}

#[then("the consent start response sends the browser to the identity provider")]
fn consent_start_response_sends_browser_to_identity_provider(world: &mut SurfaceWorld) {
    let location = recorded_location(world, "consent start response");
    let identity_provider = identity_provider(world);
    assert_eq!(
        without_query(&location),
        identity_provider.authorization_endpoint(),
        "expected the consent start response to send the browser to the identity provider, got {location}"
    );
    assert_eq!(query_value(&location, "client_id"), OIDC_CLIENT_ID, "the sign-in names the login client");
    assert_eq!(query_value(&location, "scope"), "openid", "the sign-in asks for an ID token");
    assert!(!query_value(&location, "nonce").is_empty(), "the sign-in carries a nonce");
    assert!(
        world
            .caller_response
            .as_ref()
            .and_then(|response| response
                .headers
                .get("set-cookie"))
            .is_some_and(|cookie| cookie.starts_with("__Host-ag_consent_")),
        "expected the consent start response to set the consent binding cookie"
    );
}

#[then(
    "the consent start response asks the identity provider to send the browser back to the consent confirmation callback"
)]
fn consent_start_response_returns_to_confirmation_callback(world: &mut SurfaceWorld) {
    let location = recorded_location(world, "consent start response");
    assert_eq!(
        query_value(&location, "redirect_uri"),
        format!("{}/confirm", oauth_callback_url(world)),
        "expected the identity provider to send the browser back to the consent confirmation callback"
    );
}

/// The browser goes to the OAuth provider's authorization endpoint, asked to
/// come back to the provider's own OAuth callback.
fn assert_sends_browser_to_oauth_provider(
    world: &SurfaceWorld,
    what: &str,
    provider: &str,
) {
    let location = recorded_location(world, what);
    let base_url = world
        .surface_config
        .oauth_provider_base_url
        .as_ref()
        .expect("the OAuth provider must be running");
    assert_eq!(
        without_query(&location),
        format!("{base_url}/authorize"),
        "expected the {what} to send the browser to OAuth provider '{provider}', got {location}"
    );
    assert_eq!(
        query_value(&location, "redirect_uri"),
        oauth_callback_url(world),
        "expected OAuth provider '{provider}' to send the browser back to its OAuth callback"
    );
}

#[then(expr = "the consent start response sends the browser to OAuth provider {string}")]
fn consent_start_response_sends_browser_to_oauth_provider(
    world: &mut SurfaceWorld,
    provider: String,
) {
    assert_sends_browser_to_oauth_provider(world, "consent start response", &provider);
}

#[then(expr = "the OAuth callback response sends the browser to OAuth provider {string}")]
fn oauth_callback_response_sends_browser_to_oauth_provider(
    world: &mut SurfaceWorld,
    provider: String,
) {
    assert_sends_browser_to_oauth_provider(world, "OAuth callback response", &provider);
}

#[then(expr = "the OAuth callback response does not send the browser to OAuth provider {string}")]
fn oauth_callback_response_does_not_send_browser_to_oauth_provider(
    world: &mut SurfaceWorld,
    provider: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("a response must be recorded");
    assert_eq!(
        response
            .headers
            .get("location"),
        None,
        "expected the OAuth callback response not to send the browser to OAuth provider '{provider}'"
    );
}
