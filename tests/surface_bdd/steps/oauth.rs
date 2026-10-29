//! Steps for an Access Point that declares the authorization server of its
//! source authentication: the card security it declares, its protected
//! resource metadata, and the challenges a refused caller gets.

use cucumber::{given, then};
use serde_json::{Value, json};

use crate::bdd_support::actors::{PRIMARY_COLLABORATOR_KEY, SECONDARY_COLLABORATOR_KEY, TargetActorKind};
use crate::bdd_support::config::gateway_bootstrap::declared_access_point_url;
use crate::world::{
    JwtSourceAuthConfig, RecordedResponse, RequestPolicyFixture, SurfaceSourceAuthConfig, SurfaceWorld,
};

const PROTECTED_RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";
const GATEWAY_SCHEME: &str = "agent_gateway";
const AGENT_SCHEME: &str = "agent_own";
const CARD_SECURITY_KEYS: [&str; 5] =
    ["security", "securitySchemes", "securityRequirements", "security_schemes", "security_requirements"];

fn jwt_config(world: &mut SurfaceWorld) -> &mut JwtSourceAuthConfig {
    match world
        .surface_config
        .source_auth
        .as_mut()
    {
        Some(SurfaceSourceAuthConfig::JwtBearer(config)) => config,
        _ => panic!("JWT Bearer source authentication must be configured first"),
    }
}

fn issuer(world: &SurfaceWorld) -> String {
    match &world
        .surface_config
        .source_auth
    {
        Some(SurfaceSourceAuthConfig::JwtBearer(config)) => config.issuer.clone(),
        _ => panic!("JWT Bearer source authentication must be configured first"),
    }
}

fn gateway_port(world: &SurfaceWorld) -> u16 {
    world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        .gateway_port
}

fn access_point_url(world: &SurfaceWorld) -> String {
    declared_access_point_url(gateway_port(world), &world.surface_config.route)
}

fn metadata_url(world: &SurfaceWorld) -> String {
    format!(
        "{}{PROTECTED_RESOURCE_METADATA_PATH}{}",
        declared_access_point_url(gateway_port(world), ""),
        world.surface_config.route
    )
}

fn response(world: &SurfaceWorld) -> &RecordedResponse {
    world
        .caller_response
        .as_ref()
        .expect("the caller must have received a response")
}

fn card(world: &SurfaceWorld) -> &Value {
    &response(world).body
}

fn scope_list(scopes: &str) -> Vec<String> {
    scopes
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

#[given("the surface publishes the authorization server of its source authentication")]
fn surface_publishes_authorization_server(world: &mut SurfaceWorld) {
    jwt_config(world).declares_authorization_server = true;
}

#[given("the surface forwards the caller's token to its Target")]
fn surface_forwards_caller_token(world: &mut SurfaceWorld) {
    jwt_config(world).forwards_caller_token = true;
}

#[given("the surface has a policy admitting every caller")]
fn surface_has_policy_admitting_every_caller(world: &mut SurfaceWorld) {
    world
        .surface_config
        .request_policy = Some(RequestPolicyFixture::new(
        format!("bdd-admit-every-caller-{}", uuid::Uuid::new_v4()),
        "BDD policy admitting every caller",
        "package surface.policy\n\ndefault allow := true\n",
    ));
}

#[given(expr = "managed agent {string} publishes a v1.0 agent card with its own security")]
fn managed_agent_publishes_v1_card_with_security(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    world.set_primary_target_response(v1_card_with_security());
}

#[given(expr = "managed agent {string} publishes a v0.3 agent card with its own security")]
fn managed_agent_publishes_v0_3_card_with_security(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    world.set_primary_target_response(v0_3_card_with_security());
}

#[given(expr = "managed agent {string} publishes an agent card of both eras with its own security")]
fn managed_agent_publishes_card_of_both_eras(
    world: &mut SurfaceWorld,
    agent_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, TargetActorKind::ManagedAgent);
    let v1 = v1_card_with_security();
    let mut both = v0_3_card_with_security();
    both["supportedInterfaces"] = v1["supportedInterfaces"].clone();
    both["securityRequirements"] = v1["securityRequirements"].clone();
    world.set_primary_target_response(both);
}

#[given(
    regex = r#"^(managed|external) agent "([^"]+)" publishes a signed (v1\.0|v0\.3) agent card with its own security$"#
)]
fn agent_publishes_signed_card_with_security(
    world: &mut SurfaceWorld,
    kind: String,
    agent_name: String,
    era: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, agent_kind(&kind));
    let mut card = if era == "v1.0" {
        v1_card_with_security()
    } else {
        v0_3_card_with_security()
    };
    card["signatures"] = agent_signatures();
    match world
        .actors
        .target_collaborator_key(&agent_name)
    {
        PRIMARY_COLLABORATOR_KEY => world.set_primary_target_response(card),
        SECONDARY_COLLABORATOR_KEY => world.set_secondary_target_response(card),
        other => panic!("agent '{agent_name}' is served by unsupported collaborator '{other}'"),
    }
}

fn agent_kind(kind: &str) -> TargetActorKind {
    match kind {
        "managed" => TargetActorKind::ManagedAgent,
        "external" => TargetActorKind::ExternalAgent,
        other => panic!("no agent kind '{other}'"),
    }
}

fn agent_signatures() -> Value {
    json!([{ "protected": "eyJhbGciOiJFUzI1NiJ9", "signature": "agent-own-signature" }])
}

fn v1_card_with_security() -> Value {
    json!({
        "name": "secured-agent",
        "version": "1.0.0",
        "capabilities": { "extensions": [] },
        "supportedInterfaces": [
            { "url": "http://managed-agent.local/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0" }
        ],
        "securitySchemes": {
            AGENT_SCHEME: {
                "openIdConnectSecurityScheme": {
                    "openIdConnectUrl": "https://agent-idp.example/.well-known/openid-configuration"
                }
            }
        },
        "securityRequirements": [{ "schemes": { AGENT_SCHEME: { "list": [] } } }],
        "skills": [{
            "id": "echo", "name": "Echo", "description": "Echoes", "tags": [],
            "securityRequirements": [{ "schemes": { AGENT_SCHEME: { "list": [] } } }]
        }]
    })
}

fn v0_3_card_with_security() -> Value {
    json!({
        "protocolVersion": "0.3",
        "name": "secured-agent",
        "version": "1.0.0",
        "url": "http://managed-agent.local/a2a",
        "preferredTransport": "JSONRPC",
        "capabilities": { "extensions": [] },
        "securitySchemes": { AGENT_SCHEME: { "type": "apiKey", "in": "header", "name": "x-agent-key" } },
        "security": [{ AGENT_SCHEME: [] }],
        "skills": [{
            "id": "echo", "name": "Echo", "description": "Echoes", "tags": [],
            "security": [{ AGENT_SCHEME: [] }]
        }]
    })
}

fn assert_gateway_scheme_scopes(
    scheme: &Value,
    scopes: &[String],
    issuer: &str,
) {
    assert_eq!(
        scheme["oauth2MetadataUrl"],
        format!("{issuer}/.well-known/oauth-authorization-server"),
        "scheme was {scheme}"
    );
    let flow = &scheme["flows"]["clientCredentials"];
    assert_eq!(flow["tokenUrl"], format!("{issuer}/token"), "scheme was {scheme}");
    let mut declared: Vec<&str> = flow["scopes"]
        .as_object()
        .unwrap_or_else(|| panic!("flow scopes must be an object: {flow}"))
        .keys()
        .map(String::as_str)
        .collect();
    let mut expected: Vec<&str> = scopes
        .iter()
        .map(String::as_str)
        .collect();
    declared.sort_unstable();
    expected.sort_unstable();
    assert_eq!(declared, expected, "scheme was {scheme}");
}

fn assert_skills_carry_no_security(card: &Value) {
    assert!(
        card["skills"]
            .as_array()
            .into_iter()
            .flatten()
            .all(|skill| skill
                .get("security")
                .is_none()
                && skill
                    .get("securityRequirements")
                    .is_none()),
        "skills must not keep the managed agent's security: {card}"
    );
}

fn assert_only_gateway_scheme(card: &Value) {
    let schemes = card["securitySchemes"]
        .as_object()
        .unwrap_or_else(|| panic!("card must declare securitySchemes: {card}"));
    assert_eq!(
        schemes
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [GATEWAY_SCHEME],
        "card was {card}"
    );
    assert_skills_carry_no_security(card);
}

#[then(expr = "the agent card declares the surface authorization server for scopes {string} in the 1.0 shape")]
fn card_declares_in_1_0_shape(
    world: &mut SurfaceWorld,
    scopes: String,
) {
    let scopes = scope_list(&scopes);
    let card = card(world);
    assert_only_gateway_scheme(card);
    assert_gateway_scheme_scopes(
        &card["securitySchemes"][GATEWAY_SCHEME]["oauth2SecurityScheme"],
        &scopes,
        &issuer(world),
    );
    assert_eq!(
        card["securityRequirements"],
        json!([{ "schemes": { GATEWAY_SCHEME: { "list": scopes } } }]),
        "card was {card}"
    );
    assert!(card.get("security").is_none(), "a 1.0 card carries no flat security: {card}");
}

#[then(expr = "the agent card declares the surface authorization server for scopes {string} in the 0.3 shape")]
fn card_declares_in_0_3_shape(
    world: &mut SurfaceWorld,
    scopes: String,
) {
    let scopes = scope_list(&scopes);
    let card = card(world);
    assert_only_gateway_scheme(card);
    let scheme = &card["securitySchemes"][GATEWAY_SCHEME];
    assert_eq!(scheme["type"], "oauth2", "card was {card}");
    assert_gateway_scheme_scopes(scheme, &scopes, &issuer(world));
    assert_eq!(card["security"], json!([{ GATEWAY_SCHEME: scopes }]), "card was {card}");
    assert!(
        card.get("securityRequirements")
            .is_none(),
        "a 0.3 card carries no securityRequirements: {card}"
    );
}

#[then(expr = "the agent card declares the surface authorization server for scopes {string} in both shapes")]
fn card_declares_in_both_shapes(
    world: &mut SurfaceWorld,
    scopes: String,
) {
    let scopes = scope_list(&scopes);
    let card = card(world);
    assert_only_gateway_scheme(card);
    let scheme = &card["securitySchemes"][GATEWAY_SCHEME];
    assert_eq!(scheme["type"], "oauth2", "card was {card}");
    assert_gateway_scheme_scopes(scheme, &scopes, &issuer(world));
    assert_eq!(card["security"], json!([{ GATEWAY_SCHEME: scopes.clone() }]), "card was {card}");
    assert_eq!(
        card["securityRequirements"],
        json!([{ "schemes": { GATEWAY_SCHEME: { "list": scopes } } }]),
        "card was {card}"
    );
}

#[then("the agent card keeps the security of the managed agent")]
fn card_keeps_agent_security(world: &mut SurfaceWorld) {
    let card = card(world);
    let (published, requirement_key) = if card
        .get("securityRequirements")
        .is_some()
    {
        (v1_card_with_security(), "securityRequirements")
    } else {
        (v0_3_card_with_security(), "security")
    };
    assert_eq!(card["securitySchemes"], published["securitySchemes"], "card was {card}");
    assert_eq!(card[requirement_key], published[requirement_key], "card was {card}");
    assert_eq!(card["skills"][0][requirement_key], published["skills"][0][requirement_key], "card was {card}");
}

#[then("the agent card carries no signature")]
fn card_carries_no_signature(world: &mut SurfaceWorld) {
    let card = card(world);
    assert!(
        card.get("signatures")
            .is_none(),
        "the card must not keep a signature the gateway's rewrite invalidates: {card}"
    );
}

#[then(regex = r#"^the agent card keeps the signature of (managed|external) agent "([^"]+)"$"#)]
fn card_keeps_agent_signature(
    world: &mut SurfaceWorld,
    kind: String,
    agent_name: String,
) {
    world
        .actors
        .expect_target_kind(&agent_name, agent_kind(&kind));
    let card = card(world);
    assert_eq!(card["signatures"], agent_signatures(), "the card must keep the signature of '{agent_name}': {card}");
}

#[then("the agent card carries no security declaration")]
fn card_carries_no_security_declaration(world: &mut SurfaceWorld) {
    let card = card(world);
    for key in CARD_SECURITY_KEYS {
        assert!(card.get(key).is_none(), "the card must not declare {key}: {card}");
    }
    assert_skills_carry_no_security(card);
}

#[then("the agent card names the surface Access Point URL as its endpoint")]
fn card_names_access_point_url_as_endpoint(world: &mut SurfaceWorld) {
    let card = card(world);
    let endpoint = card
        .pointer("/supportedInterfaces/0/url")
        .or_else(|| card.get("url"))
        .and_then(Value::as_str);
    assert_eq!(endpoint, Some(access_point_url(world).as_str()), "card was {card}");
}

#[then("the protected resource metadata names the surface Access Point URL as its resource")]
fn metadata_names_access_point_url(world: &mut SurfaceWorld) {
    assert_eq!(response(world).body["resource"], access_point_url(world), "metadata was {}", response(world).body);
}

#[then("the protected resource metadata lists the authorization server of the surface")]
fn metadata_lists_authorization_server(world: &mut SurfaceWorld) {
    assert_eq!(
        response(world).body["authorization_servers"],
        json!([issuer(world)]),
        "metadata was {}",
        response(world).body
    );
}

#[then("the protected resource metadata accepts bearer tokens in the Authorization header")]
fn metadata_accepts_header_bearer_tokens(world: &mut SurfaceWorld) {
    assert_eq!(
        response(world).body["bearer_methods_supported"],
        json!(["header"]),
        "metadata was {}",
        response(world).body
    );
}

/// The challenge a declaring Access Point sends: its metadata URL, the error once
/// a token was presented, and `scope=` only when scopes are required.
fn expected_challenge(
    world: &SurfaceWorld,
    error: Option<&str>,
    scopes: &str,
) -> String {
    let mut challenge = format!("Bearer resource_metadata=\"{}\"", metadata_url(world));
    if let Some(error) = error {
        challenge.push_str(&format!(", error=\"{error}\""));
    }
    if !scopes.is_empty() {
        challenge.push_str(&format!(", scope=\"{scopes}\""));
    }
    challenge
}

fn assert_challenge(
    world: &SurfaceWorld,
    expected: &str,
) {
    let challenges: Vec<&str> = response(world)
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("www-authenticate"))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(challenges, [expected], "expected challenge {expected:?}, got {challenges:?}");
}

#[then(expr = "the response challenges the caller to authorize for scopes {string}")]
fn response_challenges_caller(
    world: &mut SurfaceWorld,
    scopes: String,
) {
    assert_challenge(world, &expected_challenge(world, None, &scopes));
}

#[then(expr = "the response challenges the caller with error {string} for scopes {string}")]
fn response_challenges_caller_with_error(
    world: &mut SurfaceWorld,
    error: String,
    scopes: String,
) {
    assert_challenge(world, &expected_challenge(world, Some(&error), &scopes));
}
