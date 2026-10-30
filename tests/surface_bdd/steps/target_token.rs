//! Steps for Target Authentication through an OAuth provider: the gateway
//! obtains its own access token and sends it to the managed agent.

use std::collections::HashMap;

use cucumber::gherkin::Step;
use cucumber::{given, then, when};

use crate::bdd_support::actors::TargetActorKind;
use crate::bdd_support::config::target_auth::{
    JwtBearerAssertionFixture, TargetTokenGrant, TargetTokenProviderFixture, signing_key_secret_id,
};
use crate::bdd_support::mock_server::ReceivedRequest;
use crate::bdd_support::oidc::{
    AcceptedAssertion, AssertionAlgorithm, AssertionSigningKey, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OidcProvider,
};
use crate::steps::when::{ensure_admin_session, fetch_agent_card, request_with_valid_api_key};
use crate::world::{SurfaceTargetTokenAuthConfig, SurfaceWorld};

const ASSERTION_KEY_ID: &str = "bdd-gateway-key";
const TARGET_AUTH_FAILED: &str = "Target authentication failed";

fn configure_gateway_token(
    world: &mut SurfaceWorld,
    provider_name: String,
    provider: OidcProvider,
    grant: TargetTokenGrant,
    fallback: &str,
) {
    world
        .surface_config
        .target_token_auth = Some(SurfaceTargetTokenAuthConfig {
        provider: TargetTokenProviderFixture {
            provider_id: provider_name.clone(),
            token_endpoint: provider.token_endpoint(),
            grant,
        },
        fallback: fallback.to_string(),
    });
    world
        .oauth_providers
        .insert(provider_name, provider);
}

async fn surface_sends_gateway_token(
    world: &mut SurfaceWorld,
    provider_name: String,
    fallback: &str,
) {
    let provider = OidcProvider::start().await;
    let grant = TargetTokenGrant::client_credentials(OIDC_CLIENT_ID, OIDC_CLIENT_SECRET);
    configure_gateway_token(world, provider_name, provider, grant, fallback);
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

fn assertion_settings(step: &Step) -> HashMap<String, String> {
    step.table
        .as_ref()
        .expect("step must have a table of assertion settings")
        .rows
        .iter()
        .map(|row| match row.as_slice() {
            [name, value] => (name.trim().to_string(), value.trim().to_string()),
            other => panic!("assertion setting rows have a name and a value, got {other:?}"),
        })
        .collect()
}

/// The provider grants the token for an assertion signed with a key it trusts for the
/// configured issuer and subject; the table also sets the surface's fallback (default `reject`).
#[given(expr = "the surface sends its Target a gateway token from OAuth provider {string} for a signed assertion")]
async fn surface_sends_gateway_token_for_signed_assertion(
    world: &mut SurfaceWorld,
    provider_name: String,
    step: &Step,
) {
    let settings = assertion_settings(step);
    let setting = |name: &str| {
        settings
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("assertion setting '{name}' is required"))
    };
    let algorithm: AssertionAlgorithm = setting("algorithm")
        .parse()
        .unwrap_or_else(|error| panic!("{error}"));
    let (issuer, subject) = (setting("issuer"), setting("subject"));
    let fallback = settings
        .get("fallback")
        .map_or("reject", String::as_str)
        .to_string();
    let key = AssertionSigningKey::for_algorithm(algorithm);
    let provider = OidcProvider::start().await;
    provider.trust_assertion_signer(&issuer, &subject, ASSERTION_KEY_ID, key);
    let grant = TargetTokenGrant::JwtBearer(JwtBearerAssertionFixture {
        issuer,
        subject,
        algorithm: algorithm.as_str().to_string(),
        key_id: ASSERTION_KEY_ID.to_string(),
        signing_key_pem: key
            .private_pkcs8_pem()
            .to_string(),
    });
    configure_gateway_token(world, provider_name, provider, grant, &fallback);
}

#[given(expr = "OAuth provider {string} no longer trusts the gateway signing key")]
fn oauth_provider_distrusts_signing_key(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    provider(world, &provider_name).distrust_assertion_signer();
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

async fn read_through_admin_api(
    world: &mut SurfaceWorld,
    path: &str,
) {
    ensure_admin_session(world).await;
    let response = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_recorded_json::<serde_json::Value>(reqwest::Method::GET, path, None)
        .await
        .unwrap_or_else(|error| panic!("read {path} through admin API: {error}"));
    world.admin_response = Some(response);
}

#[when(expr = "the operator reads OAuth provider {string} through the admin API")]
async fn operator_reads_oauth_provider(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    read_through_admin_api(world, &format!("/api/v1/credential-providers/{provider_name}")).await;
}

#[when(expr = "the operator reads the signing key secret of OAuth provider {string} through the admin API")]
async fn operator_reads_signing_key_secret(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    read_through_admin_api(world, &format!("/api/v1/secrets/{}", signing_key_secret_id(&provider_name))).await;
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

#[then(regex = r#"^OAuth provider "([^"]+)" accepted (\d+) assertions?$"#)]
fn oauth_provider_accepted_assertions(
    world: &mut SurfaceWorld,
    provider_name: String,
    expected: usize,
) {
    assert_eq!(
        provider(world, &provider_name)
            .accepted_assertions()
            .len(),
        expected
    );
}

fn accepted_assertions(
    world: &SurfaceWorld,
    provider_name: &str,
) -> Vec<AcceptedAssertion> {
    let accepted = provider(world, provider_name).accepted_assertions();
    assert!(!accepted.is_empty(), "OAuth provider '{provider_name}' accepted no assertion");
    accepted
}

#[then(expr = "every assertion OAuth provider {string} accepted is signed with {string}")]
fn every_assertion_signed_with(
    world: &mut SurfaceWorld,
    provider_name: String,
    algorithm: String,
) {
    for assertion in accepted_assertions(world, &provider_name) {
        assert_eq!(assertion.algorithm.as_str(), algorithm);
        assert_eq!(assertion.key_id.as_deref(), Some(ASSERTION_KEY_ID));
    }
}

#[then(regex = r#"^every assertion OAuth provider "([^"]+)" accepted has (issuer|subject) "([^"]+)"$"#)]
fn every_assertion_has_claim(
    world: &mut SurfaceWorld,
    provider_name: String,
    claim: String,
    expected: String,
) {
    let claim_name = if claim == "issuer" {
        "iss"
    } else {
        "sub"
    };
    for assertion in accepted_assertions(world, &provider_name) {
        assert_eq!(
            assertion.claims[claim_name].as_str(),
            Some(expected.as_str()),
            "{claim} of assertion {}",
            assertion.claims
        );
    }
}

#[then(expr = "every assertion OAuth provider {string} accepted is addressed to its token endpoint")]
fn every_assertion_addressed_to_token_endpoint(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    let token_endpoint = provider(world, &provider_name).token_endpoint();
    for assertion in accepted_assertions(world, &provider_name) {
        assert_eq!(assertion.claims["aud"].as_str(), Some(token_endpoint.as_str()), "aud of {}", assertion.claims);
    }
}

#[then(expr = "every assertion OAuth provider {string} accepted expires within {int} seconds")]
fn every_assertion_expires_within(
    world: &mut SurfaceWorld,
    provider_name: String,
    max_seconds: u64,
) {
    for assertion in accepted_assertions(world, &provider_name) {
        let expires_at = assertion.claims["exp"]
            .as_u64()
            .unwrap_or_else(|| panic!("assertion has no numeric exp: {}", assertion.claims));
        let remaining = expires_at.saturating_sub(assertion.received_at);
        assert!(
            remaining > 0 && remaining <= max_seconds,
            "assertion received at {} expires at {expires_at}, expected within {max_seconds} seconds",
            assertion.received_at
        );
    }
}

fn caller_response(world: &SurfaceWorld) -> &crate::world::RecordedResponse {
    world
        .caller_response
        .as_ref()
        .expect("caller_response must be set")
}

#[then("the response body reports only that Target authentication failed")]
fn response_reports_only_target_auth_failure(world: &mut SurfaceWorld) {
    assert_eq!(
        caller_response(world).body,
        serde_json::json!({
            "type": "https://a2a-protocol.org/errors/proxy-error",
            "title": "Bad Gateway",
            "status": 502,
            "detail": TARGET_AUTH_FAILED,
        })
    );
}

fn signing_key(world: &SurfaceWorld) -> &'static AssertionSigningKey {
    match world
        .surface_config
        .target_token_auth
        .as_ref()
        .map(|auth| &auth.provider.grant)
    {
        Some(TargetTokenGrant::JwtBearer(assertion)) => AssertionSigningKey::for_algorithm(
            assertion
                .algorithm
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        ),
        _ => panic!("the surface must send a gateway token for a signed assertion"),
    }
}

/// Fails when `text` holds the private key, or any line of it.
fn assert_no_signing_key(
    world: &SurfaceWorld,
    text: &str,
    context: &str,
) {
    assert!(!text.contains("PRIVATE KEY"), "{context} contains a private key marker");
    let leaked = signing_key(world)
        .key_material_lines()
        .any(|line| text.contains(line));
    assert!(!leaked, "{context} contains signing key material");
}

#[then(
    expr = "the response does not reveal the signing key, the gateway token or the token endpoint of OAuth provider {string}"
)]
fn response_reveals_no_provider_secrets(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    let response = caller_response(world);
    let text = format!(
        "{} {}",
        response.body,
        response
            .headers
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
    );
    assert_no_signing_key(world, &text, "the response");
    let oauth_provider = provider(world, &provider_name);
    assert!(!text.contains(oauth_provider.access_token()), "the response contains the gateway token");
    let token_endpoint = oauth_provider.token_endpoint();
    let endpoint_authority = token_endpoint
        .trim_start_matches("http://")
        .trim_end_matches("/token");
    assert!(!text.contains(endpoint_authority), "the response names the token endpoint {token_endpoint}: {text}");
}

#[then(expr = "the admin API response names assertion issuer {string}")]
fn admin_response_names_assertion_issuer(
    world: &mut SurfaceWorld,
    expected: String,
) {
    let body = &world
        .admin_response
        .as_ref()
        .expect("admin_response must be set")
        .body;
    assert_eq!(body["jwt_bearer"]["assertion_issuer"].as_str(), Some(expected.as_str()), "{body}");
}

#[then(expr = "the admin API response describes the signing key secret of OAuth provider {string}")]
fn admin_response_describes_signing_key_secret(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    let body = &world
        .admin_response
        .as_ref()
        .expect("admin_response must be set")
        .body;
    assert_eq!(body["secret_id"].as_str(), Some(signing_key_secret_id(&provider_name).as_str()), "{body}");
    assert!(body.get("value").is_none(), "the secret read returned a value field");
}

#[then("the admin API response does not reveal the signing key")]
fn admin_response_reveals_no_signing_key(world: &mut SurfaceWorld) {
    let response = world
        .admin_response
        .as_ref()
        .expect("admin_response must be set");
    let text = response.body.to_string();
    assert_no_signing_key(world, &text, "the admin API response");
}
