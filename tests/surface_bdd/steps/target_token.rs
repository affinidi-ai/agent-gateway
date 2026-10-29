//! Steps for Target Authentication through an OAuth provider: the gateway
//! obtains its own access token and sends it to the managed agent.

use cucumber::{given, then};

use crate::bdd_support::actors::TargetActorKind;
use crate::bdd_support::config::target_auth::TargetTokenProviderFixture;
use crate::bdd_support::mock_server::ReceivedRequest;
use crate::bdd_support::oidc::{OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OidcProvider};
use crate::steps::when::{fetch_agent_card, request_with_valid_api_key};
use crate::world::{SurfaceTargetTokenAuthConfig, SurfaceWorld};

async fn surface_sends_gateway_token(
    world: &mut SurfaceWorld,
    provider_name: String,
    fallback: &str,
) {
    let provider = OidcProvider::start().await;
    let token_auth = SurfaceTargetTokenAuthConfig {
        provider: TargetTokenProviderFixture {
            provider_id: provider_name.clone(),
            token_endpoint: provider.token_endpoint(),
            client_id: OIDC_CLIENT_ID.to_string(),
            client_secret: OIDC_CLIENT_SECRET.to_string(),
        },
        fallback: fallback.to_string(),
    };
    world
        .oauth_providers
        .insert(provider_name, provider);
    world
        .surface_config
        .target_token_auth = Some(token_auth);
}

#[given(expr = "the surface sends its Target a gateway token from OAuth provider {string}")]
async fn surface_sends_gateway_token_rejecting_failures(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    surface_sends_gateway_token(world, provider_name, "reject").await;
}

#[given(expr = "the surface sends its Target a gateway token from OAuth provider {string} with fallback {string}")]
async fn surface_sends_gateway_token_with_fallback(
    world: &mut SurfaceWorld,
    provider_name: String,
    fallback: String,
) {
    surface_sends_gateway_token(world, provider_name, &fallback).await;
}

#[given("the caller has fetched the agent card")]
async fn caller_has_fetched_agent_card(world: &mut SurfaceWorld) {
    fetch_agent_card(world).await;
}

#[given("the caller has sent a request to the surface with a valid API key")]
async fn caller_has_sent_request_with_valid_api_key(world: &mut SurfaceWorld) {
    request_with_valid_api_key(world).await;
}

#[given(expr = "OAuth provider {string} is unavailable")]
fn oauth_provider_is_unavailable(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    provider(world, &provider_name).take_token_endpoint_down();
}

fn provider<'a>(
    world: &'a SurfaceWorld,
    provider_name: &str,
) -> &'a OidcProvider {
    world
        .oauth_providers
        .get(provider_name)
        .unwrap_or_else(|| panic!("unknown OAuth provider '{provider_name}'"))
}

fn received_requests<'a>(
    world: &'a SurfaceWorld,
    agent_name: &str,
) -> &'a [ReceivedRequest] {
    world
        .actors
        .expect_target_kind(agent_name, TargetActorKind::ManagedAgent);
    world
        .collaborator_target(
            world
                .actors
                .target_collaborator_key(agent_name),
        )
        .observations
        .as_ref()
        .unwrap_or_else(|| panic!("managed agent '{agent_name}' observations must be recorded"))
        .requests
        .as_slice()
}

fn authorization(request: &ReceivedRequest) -> Option<&str> {
    request
        .headers
        .get("authorization")
        .map(String::as_str)
}

#[then(expr = "every request managed agent {string} received carried the gateway token from OAuth provider {string}")]
fn every_request_carried_gateway_token(
    world: &mut SurfaceWorld,
    agent_name: String,
    provider_name: String,
) {
    let expected = format!("Bearer {}", provider(world, &provider_name).access_token());
    let requests = received_requests(world, &agent_name);
    assert!(!requests.is_empty(), "managed agent '{agent_name}' received no request");
    for request in requests {
        assert_eq!(
            authorization(request),
            Some(expected.as_str()),
            "request {} {}",
            request.method,
            request.path_and_query
        );
    }
}

#[then(expr = "managed agent {string} did not receive the gateway token from OAuth provider {string}")]
fn agent_did_not_receive_gateway_token(
    world: &mut SurfaceWorld,
    agent_name: String,
    provider_name: String,
) {
    let token = provider(world, &provider_name).access_token();
    for request in received_requests(world, &agent_name) {
        assert!(
            !request
                .headers
                .values()
                .any(|value| value.contains(token)),
            "request {} {} carried the gateway token",
            request.method,
            request.path_and_query
        );
    }
}

#[then(regex = r#"^managed agent "([^"]+)" received (\d+) requests?$"#)]
fn agent_received_requests(
    world: &mut SurfaceWorld,
    agent_name: String,
    expected: usize,
) {
    assert_eq!(received_requests(world, &agent_name).len(), expected);
}

#[then(regex = r#"^OAuth provider "([^"]+)" received (\d+) token requests?$"#)]
fn oauth_provider_received_token_requests(
    world: &mut SurfaceWorld,
    provider_name: String,
    expected: u64,
) {
    assert_eq!(provider(world, &provider_name).token_request_count(), expected);
}
