use cucumber::{given, then, when};
use reqwest::Method;

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

#[when(expr = "the operator creates the authorization code provider {string} with consent confirmation")]
async fn operator_creates_provider_with_consent_confirmation(
    world: &mut SurfaceWorld,
    provider_id: String,
) {
    let body = serde_json::json!({
        "name": provider_id, "provider_id": provider_id, "provider_type": "oauth2_authorization_code",
        "authorization_endpoint": "https://192.0.2.1/authorize", "token_endpoint": "https://192.0.2.1/token",
        "client_id_secret_ref": "vendor-client-id", "client_secret_secret_ref": "vendor-client-secret",
        "consent_confirmation": {
            "client_id_secret_ref": "login-client-id", "client_secret_secret_ref": "login-client-secret",
            "authorization_endpoint": "https://192.0.2.2/authorize", "token_endpoint": "https://192.0.2.2/token",
            "jwt_verification_strategy_id": "callers"
        }
    });
    let response =
        crate::steps::credential_save::send(world, Method::POST, "/v1/credential-providers", Some(&body)).await;
    world.admin_response = Some(response);
}

/// The JWT verification strategy that verifies the surface's JWT callers, which a
/// confirming OAuth provider confirms them through.
const CALLERS_STRATEGY_ID: &str = "bdd-jwt-strategy";

#[when("the operator deletes the JWT verification strategy that confirms the callers")]
async fn operator_deletes_confirming_strategy(world: &mut SurfaceWorld) {
    let response = crate::steps::credential_save::send(
        world,
        Method::DELETE,
        &format!("/v1/jwt-verification-strategies/{CALLERS_STRATEGY_ID}"),
        None,
    )
    .await;
    world.admin_response = Some(response);
}

/// An issuer of the Microsoft identity platform, which names a caller by `sub`
/// per application.
const ENTRA_ISSUER: &str = "https://login.microsoftonline.com/bdd-tenant/v2.0";

async fn confirming_strategy(world: &mut SurfaceWorld) -> serde_json::Value {
    let read = crate::steps::credential_save::send(
        world,
        Method::GET,
        &format!("/v1/jwt-verification-strategies/{CALLERS_STRATEGY_ID}"),
        None,
    )
    .await;
    assert_eq!(read.status, 200, "read the JWT verification strategy: {}", read.body);
    read.body
}

#[when("the operator changes the issuer of the JWT verification strategy that confirms the callers to an Entra issuer")]
async fn operator_changes_confirming_strategy_issuer_to_entra(world: &mut SurfaceWorld) {
    let stored = confirming_strategy(world).await;
    let body = serde_json::json!({
        "name": stored["name"], "expected_issuer": ENTRA_ISSUER, "jwks_source": stored["jwks_source"]
    });
    let response = crate::steps::credential_save::send(
        world,
        Method::PUT,
        &format!("/v1/jwt-verification-strategies/{CALLERS_STRATEGY_ID}"),
        Some(&body),
    )
    .await;
    world.admin_response = Some(response);
}

#[then("the JWT verification strategy that confirms the callers keeps its issuer")]
async fn confirming_strategy_keeps_its_issuer(world: &mut SurfaceWorld) {
    let stored = confirming_strategy(world).await;
    assert_eq!(
        stored["expected_issuer"],
        crate::steps::when::get_jwt_source_auth_issuer(world),
        "expected the strategy to keep the issuer of the surface's callers"
    );
}

#[then("the JWT verification strategy that confirms the callers is still listed")]
async fn confirming_strategy_is_still_listed(world: &mut SurfaceWorld) {
    let listed = crate::steps::credential_save::send(world, Method::GET, "/v1/jwt-verification-strategies", None).await;
    assert_eq!(listed.status, 200, "list the JWT verification strategies: {}", listed.body);
    let ids: Vec<&str> = listed
        .body
        .as_array()
        .expect("the strategies are listed as an array")
        .iter()
        .filter_map(|strategy| strategy["id"].as_str())
        .collect();
    assert!(ids.contains(&CALLERS_STRATEGY_ID), "expected strategy {CALLERS_STRATEGY_ID} to be listed, got {ids:?}");
}

/// The id the single-surface fixture stores the surface under.
const SURFACE_ID: &str = "bdd-surface";

#[given("the operator has deleted the surface the consent link was minted on")]
async fn operator_has_deleted_consent_surface(world: &mut SurfaceWorld) {
    world.created_surface_id = Some(SURFACE_ID.to_string());
    crate::steps::when::delete_surface(world).await;
    let status = world
        .admin_response
        .as_ref()
        .map(|response| response.status);
    assert!(status.is_some_and(|status| (200..300).contains(&status)), "the operator deletes the surface: {status:?}");
}

#[given(expr = "Transit Point {string} injects delegated credentials from OAuth provider {string}")]
fn transit_point_injects_oauth_delegated_credentials(
    world: &mut SurfaceWorld,
    transit_point: String,
    provider: String,
) {
    crate::steps::given::transit_point_config_mut(world, &transit_point).delegated_credentials = true;
    crate::steps::given::surface_requires_oauth_delegated_credentials(world, provider);
}

/// The audience a Transit Point's JWT callers' tokens are issued for.
const TRANSIT_AUDIENCE: &str = "bdd-transit-audience";

#[given(expr = "Transit Point {string} authenticates its callers with JWT Bearer")]
fn transit_point_authenticates_its_callers_with_jwt_bearer(
    world: &mut SurfaceWorld,
    transit_point: String,
) {
    crate::steps::given::transit_point_config_mut(world, &transit_point).source_auth = Some(serde_json::json!({
        "type": "jwt_bearer",
        "jwt_verification_strategy_id": CALLERS_STRATEGY_ID,
        "audiences": [TRANSIT_AUDIENCE],
        "forward_header": false,
    }));
}

/// The JWT caller calls the Access Point, and the managed agent then calls a
/// tool through the Transit Point with the transit token it was handed, named
/// as the managed agent, and the caller's JWT.
#[given(
    expr = "managed agent {string} has started OAuth consent for provider {string} through Transit Point {string} for JWT caller {string}"
)]
async fn managed_agent_has_started_oauth_consent_through_transit_point(
    world: &mut SurfaceWorld,
    agent_name: String,
    _provider: String,
    transit_point: String,
    caller: String,
) {
    ensure_gateway_running(world).await;
    let access_point_token =
        crate::steps::when::create_valid_jwt_for_subject_with_world_claims(world, &caller, serde_json::json!({}));
    crate::steps::when::send_request_and_record(
        world,
        vec![("authorization".to_string(), format!("Bearer {access_point_token}"))],
    )
    .await;
    let transit_token = world
        .infra
        .as_ref()
        .expect("scenario infra must exist")
        .mock
        .last_request()
        .await
        .and_then(|forwarded| {
            forwarded
                .headers
                .get("x-transit-token")
                .cloned()
        })
        .expect("the Access Point hands the managed agent a transit token");
    let transit_token = crate::steps::when::reissued_transit_token(
        world,
        &transit_token,
        serde_json::json!({ "sub": format!("did:web:{agent_name}.example") }),
    );
    let token = crate::steps::when::create_valid_jwt_for_subject_with_world_claims(
        world,
        &caller,
        serde_json::json!({ "aud": TRANSIT_AUDIENCE }),
    );
    let body = crate::bdd_support::json_rpc::build_mcp_tool_call_body("schedule_meeting", serde_json::json!({}));
    crate::steps::when::send_mcp_request_through_transit_point_path_with_headers(
        world,
        &agent_name,
        &format!("/transit/{transit_point}"),
        body,
        vec![("x-transit-token".to_string(), transit_token), ("authorization".to_string(), format!("Bearer {token}"))],
    )
    .await;
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
