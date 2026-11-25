use cucumber::{given, then, when};
use serde_json::{Value, json};

use crate::bdd_support::actors::TargetActorKind;
use crate::bdd_support::assertions::assert_json_body_mentions;
use crate::bdd_support::config::config_tree::PolicyDefinitionFixture;
use crate::bdd_support::config::single_surface_fixture::{
    ApiKeyProviderSourceAuthConfig, OutboundClientCertificatesFixture, StoredApiKeyFixture, SurfaceSourceAuthConfig,
};
use crate::bdd_support::json_rpc::{
    attach_agent_identity_payload, build_a2a_message_send_body, build_mcp_tool_call_body,
};
use crate::bdd_support::jwt;
use crate::bdd_support::mock_server::{MockTls, TestCertificateAuthority, client_presenting_certificate};
use crate::steps::given::transit_point_config_mut;
use crate::steps::target_auth_save::{create_caller_jwt_strategy, draft_transit_point};
use crate::steps::target_credential::before_the_gateway_starts;
use crate::steps::then::{
    first_credential_subject_from_vp, get_a2a_binding_extension, get_admin_response, get_did_from_a2a_binding_request,
    get_holder_did_from_vp, get_observed_request_for_actor, get_observed_target_for_actor,
    get_observed_target_requests, is_valid_vp,
};
use crate::steps::when::{
    build_primary_target_surface_payload, ensure_admin_session, ensure_gateway_running, record_transit_point_response,
    send_a2a_body_through_transit_point, send_a2a_body_through_transit_point_path, send_a2a_proxy_request_and_record,
    send_mcp_request_through_transit_point_path_with_headers, transit_point_path,
};
use crate::world::SurfaceWorld;

const API_KEY_HEADER: &str = "X-API-Key";
const DRAFT_TARGET: &str = "http://127.0.0.1:9/";
const IDENTITY_CREDENTIAL_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity-credential/v1";
const MCP_IDENTITY_CREDENTIAL_KEY: &str = "io.affinidi.fabric/agent-identity-credential";
const IDENTITY_BINDING_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity-binding/v1";
const MCP_IDENTITY_BINDING_KEY: &str = "io.affinidi.fabric/agent-identity-binding";

/// The id of the API Key Provider key a scenario calls `name`.
fn key_id(name: &str) -> String {
    format!("atgk_bdd_{}", name.replace('-', "_"))
}

/// The value a caller presents for key `name`, as the stored key fixture records it.
fn key_value(name: &str) -> String {
    format!("bdd-secret-{}", key_id(name))
}

fn api_key_provider_source_auth(provider: &str) -> Value {
    json!({
        "type": "api_key_provider",
        "extraction": { "source": "http_header", "field": API_KEY_HEADER },
        "agent_id": provider,
    })
}

/// The API Key Provider agent Transit Point `transit_point` checks its callers' keys with.
fn transit_point_provider(
    world: &mut SurfaceWorld,
    transit_point: &str,
) -> String {
    transit_point_config_mut(world, transit_point)
        .source_auth
        .as_ref()
        .and_then(|source_auth| source_auth["agent_id"].as_str())
        .unwrap_or_else(|| {
            panic!("Transit Point '{transit_point}' must authenticate its callers with an API key provider")
        })
        .to_string()
}

/// Stores key `name` of API Key Provider agent `provider` before the gateway starts, once.
fn provider_key(
    world: &mut SurfaceWorld,
    provider: &str,
    name: &str,
) -> (String, String) {
    if !world
        .api_keys
        .contains_key(name)
    {
        before_the_gateway_starts(world, "an API key a caller presents");
        world
            .surface_config
            .stored_api_keys
            .push(StoredApiKeyFixture {
                owner: provider.to_string(),
                key_id: key_id(name),
                created_at: chrono::Utc::now() - chrono::Duration::days(1),
                loads: true,
            });
        world
            .api_keys
            .insert(name.to_string(), (provider.to_string(), key_id(name)));
    }
    (API_KEY_HEADER.to_string(), key_value(name))
}

/// The managed agent the surface targets, which calls its Transit Points.
fn managed_agent(world: &SurfaceWorld) -> String {
    world
        .actors
        .targets()
        .values()
        .find(|target| target.kind == TargetActorKind::ManagedAgent)
        .map(|target| target.key.clone())
        .expect("the surface must have a managed agent to call its Transit Points")
}

/// The external agent the scenario's Transit Point calls.
fn external_agent(world: &SurfaceWorld) -> String {
    world
        .actors
        .targets()
        .values()
        .find(|target| target.kind == TargetActorKind::ExternalAgent)
        .map(|target| target.key.clone())
        .expect("the scenario has an external agent")
}

/// A message/send request, carrying the copied identity extension when the scenario has one:
/// the message metadata and extensions another agent's request presented to the destination.
fn transit_point_request_body(world: &SurfaceWorld) -> Value {
    let mut body = build_a2a_message_send_body("hello");
    if let Some(copied) = world
        .copied_identity_extension
        .as_ref()
    {
        body["params"]["message"]["metadata"] = copied["metadata"].clone();
        body["params"]["message"]["extensions"] = copied["extensions"].clone();
    }
    body
}

/// A tools/call request for `tool`, carrying the copied identity in `_meta` when the scenario
/// has one: the metadata another agent's request presented to the destination.
fn transit_point_mcp_request_body(
    world: &SurfaceWorld,
    tool: &str,
) -> Value {
    let mut body = build_mcp_tool_call_body(tool, json!({ "limit": 3 }));
    if let Some(copied) = world
        .copied_identity_extension
        .as_ref()
    {
        if !copied["meta"].is_null() {
            body["_meta"] = copied["meta"].clone();
        }
        if !copied["params_meta"].is_null() {
            body["params"]["_meta"] = copied["params_meta"].clone();
        }
    }
    body
}

/// The DID the gateway issued for key `name`, as the Identities dashboard lists it.
async fn issued_did_of_key(
    world: &mut SurfaceWorld,
    name: &str,
) -> String {
    ensure_admin_session(world).await;
    let stats: Value = world
        .admin_client
        .as_ref()
        .expect("admin client must exist")
        .send_json::<(), _>(reqwest::Method::GET, "/v1/dashboard/stats", None)
        .await
        .unwrap_or_else(|error| panic!("read the Identities dashboard: {error}"));
    let key_id = key_id(name);
    stats["identities"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|identity| identity["agent_identity"]["api_key_id"] == key_id.as_str())
        .and_then(|identity| identity["did"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("the gateway should list a DID for key '{name}' ({key_id}), got: {stats}"))
}

#[given(expr = "Transit Point {string} authenticates its callers with an API key of API key provider {string}")]
fn transit_point_authenticates_callers_with_provider_key(
    world: &mut SurfaceWorld,
    transit_point: String,
    provider: String,
) {
    transit_point_config_mut(world, &transit_point).source_auth = Some(api_key_provider_source_auth(&provider));
}

#[given(expr = "surface {string} authenticates its callers with an API key of API key provider {string}")]
fn surface_authenticates_callers_with_provider_key(
    world: &mut SurfaceWorld,
    surface: String,
    provider: String,
) {
    assert!(
        world
            .actors
            .surface(&surface)
            .is_some(),
        "unknown surface '{surface}'"
    );
    world
        .surface_config
        .source_auth = Some(SurfaceSourceAuthConfig::ApiKeyProvider(ApiKeyProviderSourceAuthConfig {
        header_name: API_KEY_HEADER.to_string(),
        agent_id: provider,
        key_id: key_id("access-point-default"),
        client_id: "bdd-client".to_string(),
        valid_key: key_value("access-point-default"),
    }));
}

#[given(expr = "Transit Point {string} takes the managed agent's identity from its caller's API key")]
fn transit_point_takes_identity_from_caller_api_key(
    world: &mut SurfaceWorld,
    transit_point: String,
) {
    transit_point_config_mut(world, &transit_point).identity_from_caller_api_key = true;
}

#[given(
    expr = "Transit Point {string} has a policy that admits only a managed agent whose identity verification is {string}"
)]
fn transit_point_admits_only_managed_agent_verified_by(
    world: &mut SurfaceWorld,
    transit_point: String,
    verification: String,
) {
    let verification_literal = serde_json::to_string(&verification).expect("verification should serialize");
    let rego = format!(
        r#"package surface.policy

default allow := false

allow if input.extension_identity.verification == {verification_literal}
"#
    );
    transit_point_config_mut(world, &transit_point).policy = Some(PolicyDefinitionFixture::new(
        format!("bdd-transit-managed-agent-{}", uuid::Uuid::new_v4()),
        "BDD Transit Point policy: admit only a verified managed agent",
        &rego,
    ));
}

#[given(expr = "surface {string}'s inbound identity takes its DID from the caller's API key")]
fn surface_inbound_identity_from_caller_api_key(
    world: &mut SurfaceWorld,
    surface: String,
) {
    assert!(
        world
            .actors
            .surface(&surface)
            .is_some(),
        "unknown surface '{surface}'"
    );
    world
        .surface_config
        .api_key_inbound_identity = true;
}

#[given(
    expr = "surface {string} was stored with its inbound Identity taking its DID from a client certificate it does not name"
)]
fn surface_stored_with_inbound_identity_from_unnamed_certificate(
    world: &mut SurfaceWorld,
    surface: String,
) {
    assert!(
        world
            .actors
            .surface(&surface)
            .is_some(),
        "unknown surface '{surface}'"
    );
    before_the_gateway_starts(world, "the stored surface's inbound Identity");
    world
        .surface_config
        .inbound_identity_from_unnamed_certificate = true;
}

#[given(expr = "surface {string} gives its callers the static DID {string}")]
fn surface_gives_callers_static_did(
    world: &mut SurfaceWorld,
    surface: String,
    did: String,
) {
    assert!(
        world
            .actors
            .surface(&surface)
            .is_some(),
        "unknown surface '{surface}'"
    );
    world
        .surface_config
        .inbound_static_did = Some(did);
}

#[given(expr = "surface {string} has a policy that admits only caller DID {string} without an identity hash")]
fn surface_admits_only_did_without_identity_hash(
    world: &mut SurfaceWorld,
    surface: String,
    did: String,
) {
    assert!(
        world
            .actors
            .surface(&surface)
            .is_some(),
        "unknown surface '{surface}'"
    );
    let did_literal = serde_json::to_string(&did).expect("the DID should serialize");
    let rego = format!(
        r#"package surface.policy

default allow := false

allow if {{
    input.extension_identity.did == {did_literal}
    not input.extension_identity.identity_hash
}}
"#
    );
    world
        .surface_config
        .request_policy = Some(PolicyDefinitionFixture::new(
        "bdd-static-did-without-identity-hash",
        "BDD surface policy: admit only a static DID without an identity hash",
        &rego,
    ));
}

#[given(
    expr = "surface {string} has variant {string} whose Transit Point {string} takes the managed agent's identity from its caller's API key"
)]
fn variant_transit_point_takes_identity_from_caller_api_key(
    world: &mut SurfaceWorld,
    surface: String,
    variant: String,
    transit_point: String,
) {
    assert!(
        world
            .actors
            .surface(&surface)
            .is_some(),
        "unknown surface '{surface}'"
    );
    transit_point_config_mut(world, &transit_point);
    before_the_gateway_starts(world, "the surface variant");
    world
        .surface_config
        .variant_caller_key_transit_point = Some((variant, transit_point));
}

#[given(expr = "API key provider {string} has issued key {string}")]
fn api_key_provider_has_issued_key(
    world: &mut SurfaceWorld,
    provider: String,
    key: String,
) {
    provider_key(world, &provider, &key);
}

#[given(expr = "managed agent {string} has sent a request through Transit Point {string} with key {string}")]
async fn managed_agent_has_sent_request_through_transit_point_with_key(
    world: &mut SurfaceWorld,
    agent: String,
    transit_point: String,
    key: String,
) {
    world
        .actors
        .expect_target_kind(&agent, TargetActorKind::ManagedAgent);
    let provider = transit_point_provider(world, &transit_point);
    let header = provider_key(world, &provider, &key);
    let mut body = build_a2a_message_send_body("hello");
    attach_agent_identity_payload(&mut body);
    send_a2a_body_through_transit_point(world, &agent, &transit_point, vec![header], body).await;
    let status = world
        .caller_response
        .as_ref()
        .map(|response| response.status);
    assert_eq!(status, Some(200), "managed agent '{agent}' must reach Transit Point '{transit_point}' first");
    let external = external_agent(world);
    let context = format!("external agent '{external}'");
    let request = get_observed_request_for_actor(world, &external, TargetActorKind::ExternalAgent);
    let did = get_did_from_a2a_binding_request(request, &context);
    let message = request.json_body()["params"]["message"].clone();
    world
        .presented_identity_extensions
        .insert(agent, json!({ "metadata": message["metadata"], "extensions": message["extensions"], "did": did }));
    forget_destination_requests(world).await;
}

#[given(expr = "managed agent {string} has invoked MCP tool {string} through Transit Point {string} with key {string}")]
async fn managed_agent_has_invoked_mcp_tool_through_transit_point_with_key(
    world: &mut SurfaceWorld,
    agent: String,
    tool: String,
    transit_point: String,
    key: String,
) {
    world
        .actors
        .expect_target_kind(&agent, TargetActorKind::ManagedAgent);
    let provider = transit_point_provider(world, &transit_point);
    let header = provider_key(world, &provider, &key);
    let path = transit_point_path(world, &transit_point);
    let body = build_mcp_tool_call_body(&tool, json!({ "limit": 3 }));
    send_mcp_request_through_transit_point_path_with_headers(world, &agent, &path, body, vec![header]).await;
    let response = world
        .caller_response
        .as_ref()
        .map(|response| (response.status, response.body.clone()));
    assert_eq!(
        response
            .as_ref()
            .map(|(status, _)| *status),
        Some(200),
        "managed agent '{agent}' must reach Transit Point '{transit_point}' first, got: {response:?}"
    );
    let (server, kind) = destination(world);
    let context = format!("MCP server '{server}'");
    let forwarded = get_observed_request_for_actor(world, &server, kind).json_body();
    let credential = mcp_identity_credential(&forwarded, &context);
    let vp = &credential["verifiablePresentation"];
    assert!(is_valid_vp(vp), "{context} should receive a valid identity presentation, got: {vp}");
    let did = get_holder_did_from_vp(vp);
    world
        .presented_identity_extensions
        .insert(agent, json!({ "meta": forwarded["_meta"], "params_meta": forwarded["params"]["_meta"], "did": did }));
    forget_destination_requests(world).await;
}

/// Clears what the managed agent and the Transit Point destinations have received, so a
/// scenario's later request is the only one they hold.
async fn forget_destination_requests(world: &mut SurfaceWorld) {
    let infra = world
        .infra
        .as_ref()
        .expect("the gateway runs after the first request");
    let destinations = infra
        .replacement_mock
        .iter()
        .chain(
            infra
                .transit_point_mocks
                .values(),
        );
    for mock in std::iter::once(&infra.mock).chain(destinations) {
        mock.clear_requests().await;
    }
}

#[given(expr = "the request carries a copy of managed agent {string}'s identity extension")]
fn request_carries_copied_identity_extension(
    world: &mut SurfaceWorld,
    agent: String,
) {
    world
        .actors
        .expect_target_kind(&agent, TargetActorKind::ManagedAgent);
    let presented = world
        .presented_identity_extensions
        .get(&agent)
        .cloned()
        .unwrap_or_else(|| panic!("managed agent '{agent}' must have sent a request through a Transit Point first"));
    world.copied_identity_extension = Some(presented);
}

#[given(expr = "the copy also carries an identity binding naming managed agent {string}'s DID")]
fn copy_carries_identity_binding(
    world: &mut SurfaceWorld,
    agent: String,
) {
    let copied = world
        .copied_identity_extension
        .as_mut()
        .unwrap_or_else(|| panic!("the request must carry a copy of managed agent '{agent}''s identity extension"));
    assert_eq!(
        world
            .presented_identity_extensions
            .get(&agent)
            .map(|presented| &presented["did"]),
        Some(&copied["did"]),
        "the copy must be managed agent '{agent}''s"
    );
    if copied["params_meta"].is_object() || copied["meta"].is_object() {
        let credential = mcp_identity_credential(
            &json!({ "_meta": copied["meta"], "params": { "_meta": copied["params_meta"] } }),
            "the copy",
        );
        if !copied["params_meta"].is_object() {
            copied["params_meta"] = json!({});
        }
        copied["params_meta"][MCP_IDENTITY_BINDING_KEY] = credential;
    } else {
        let credential = copied["metadata"][IDENTITY_CREDENTIAL_URI].clone();
        assert!(!credential.is_null(), "the copied metadata must carry an identity credential, got: {copied}");
        copied["metadata"][IDENTITY_BINDING_URI] = credential;
        copied["extensions"]
            .as_array_mut()
            .expect("the copied extensions must be a list")
            .push(json!(IDENTITY_BINDING_URI));
    }
}

#[then(regex = r#"^(external agent|MCP server) "([^"]+)" received no identity binding$"#)]
fn destination_received_no_identity_binding(
    world: &mut SurfaceWorld,
    kind: String,
    name: String,
) {
    let kind = if kind == "MCP server" {
        TargetActorKind::McpServer
    } else {
        TargetActorKind::ExternalAgent
    };
    let body = get_observed_request_for_actor(world, &name, kind).json_body();
    let bindings = [
        &body["params"]["message"]["metadata"][IDENTITY_BINDING_URI],
        &body["params"]["_meta"][MCP_IDENTITY_BINDING_KEY],
        &body["params"]["_meta"][IDENTITY_BINDING_URI],
        &body["_meta"][MCP_IDENTITY_BINDING_KEY],
        &body["_meta"][IDENTITY_BINDING_URI],
    ];
    assert!(
        bindings
            .iter()
            .all(|binding| binding.is_null()),
        "{kind:?} '{name}' should receive no identity binding, got body: {body}"
    );
    let extensions = &body["params"]["message"]["extensions"];
    assert!(
        !extensions
            .as_array()
            .is_some_and(|extensions| extensions.contains(&json!(IDENTITY_BINDING_URI))),
        "{kind:?} '{name}' should receive no identity binding extension, got: {extensions}"
    );
}

/// Checks the caller a step names: the surface's managed agent, or another agent the
/// scenario does not declare.
fn expect_caller(
    world: &SurfaceWorld,
    kind: &str,
    caller: &str,
) {
    let managed = managed_agent(world);
    if kind == "managed agent" {
        assert_eq!(caller, managed, "the caller must be the surface's managed agent");
    } else {
        assert_ne!(caller, managed, "agent '{caller}' must not be the surface's managed agent");
    }
}

#[when(
    regex = r#"^(managed agent|agent) "([^"]+)" sends an A2A (message/send|tasks/get) request through Transit Point "([^"]+)" with key "([^"]+)"$"#
)]
async fn caller_sends_through_transit_point_with_key(
    world: &mut SurfaceWorld,
    kind: String,
    caller: String,
    method: String,
    transit_point: String,
    key: String,
) {
    expect_caller(world, &kind, &caller);
    let provider = transit_point_provider(world, &transit_point);
    let header = provider_key(world, &provider, &key);
    let body = if method == "tasks/get" {
        json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": { "id": "task-1" } })
    } else {
        transit_point_request_body(world)
    };
    let agent = managed_agent(world);
    send_a2a_body_through_transit_point(world, &agent, &transit_point, vec![header], body).await;
}

#[when(
    expr = "managed agent {string} sends an A2A message\\/send request through Transit Point {string} of variant {string} with key {string}"
)]
async fn managed_agent_sends_through_variant_transit_point_with_key(
    world: &mut SurfaceWorld,
    agent: String,
    transit_point: String,
    variant: String,
    key: String,
) {
    expect_caller(world, "managed agent", &agent);
    let provider = transit_point_provider(world, &transit_point);
    let header = provider_key(world, &provider, &key);
    let route = world
        .surface_config
        .route
        .trim_end_matches('/')
        .to_string();
    let path = format!("/outbound{route}${variant}/{transit_point}");
    send_a2a_body_through_transit_point_path(world, &agent, &path, vec![header], build_a2a_message_send_body("hello"))
        .await;
}

#[when(expr = "a caller sends a request to the Access Point with key {string}")]
async fn caller_sends_request_to_access_point_with_key(
    world: &mut SurfaceWorld,
    key: String,
) {
    let provider = access_point_provider(world);
    let header = provider_key(world, &provider, &key);
    send_a2a_proxy_request_and_record(world, build_a2a_message_send_body("hello"), vec![header]).await;
}

#[when(
    regex = r#"^(managed agent|agent) "([^"]+)" invokes MCP tool "([^"]+)" through Transit Point "([^"]+)" with key "([^"]+)"$"#
)]
async fn caller_invokes_mcp_tool_through_transit_point_with_key(
    world: &mut SurfaceWorld,
    kind: String,
    caller: String,
    tool: String,
    transit_point: String,
    key: String,
) {
    expect_caller(world, &kind, &caller);
    let provider = transit_point_provider(world, &transit_point);
    let header = provider_key(world, &provider, &key);
    let body = transit_point_mcp_request_body(world, &tool);
    let agent = managed_agent(world);
    let path = transit_point_path(world, &transit_point);
    send_mcp_request_through_transit_point_path_with_headers(world, &agent, &path, body, vec![header]).await;
}

#[when(
    regex = r#"^(managed agent|agent) "([^"]+)" sends an A2A message/send request through Transit Point "([^"]+)" with no key$"#
)]
async fn caller_sends_through_transit_point_without_key(
    world: &mut SurfaceWorld,
    kind: String,
    caller: String,
    transit_point: String,
) {
    expect_caller(world, &kind, &caller);
    let body = transit_point_request_body(world);
    let agent = managed_agent(world);
    send_a2a_body_through_transit_point(world, &agent, &transit_point, Vec::new(), body).await;
}

/// The API Key Provider agent the surface's Access Point checks its callers' keys with.
fn access_point_provider(world: &SurfaceWorld) -> String {
    match world
        .surface_config
        .source_auth
        .as_ref()
    {
        Some(SurfaceSourceAuthConfig::ApiKeyProvider(config)) => config.agent_id.clone(),
        _ => panic!("the surface must authenticate its callers with an API key provider"),
    }
}

#[given(expr = "a caller has sent a request to the Access Point with key {string}")]
async fn caller_has_sent_request_to_access_point_with_key(
    world: &mut SurfaceWorld,
    key: String,
) {
    let provider = access_point_provider(world);
    let header = provider_key(world, &provider, &key);
    send_a2a_proxy_request_and_record(world, build_a2a_message_send_body("hello"), vec![header]).await;
    let status = world
        .caller_response
        .as_ref()
        .map(|response| response.status);
    assert_eq!(status, Some(200), "a caller with key '{key}' must reach the Access Point first");
}

/// The destination the scenario's Transit Point calls: an external agent or an MCP server.
fn destination(world: &SurfaceWorld) -> (String, TargetActorKind) {
    world
        .actors
        .targets()
        .values()
        .find(|target| matches!(target.kind, TargetActorKind::ExternalAgent | TargetActorKind::McpServer))
        .map(|target| (target.key.clone(), target.kind))
        .expect("the scenario has a Transit Point destination")
}

/// The identity credential in an MCP request's `_meta`, under either key spelling.
fn mcp_identity_credential(
    body: &Value,
    context: &str,
) -> Value {
    [&body["params"]["_meta"], &body["_meta"]]
        .into_iter()
        .flat_map(|meta| [&meta[MCP_IDENTITY_CREDENTIAL_KEY], &meta[IDENTITY_CREDENTIAL_URI]])
        .find(|credential| !credential.is_null())
        .cloned()
        .unwrap_or_else(|| panic!("{context} should receive an identity credential in _meta, got body: {body}"))
}

/// The identity presentation destination `name` received, with the DID it proves and the
/// identity fields its credential names.
fn received_identity_presentation(
    world: &SurfaceWorld,
    name: &str,
    kind: TargetActorKind,
) -> (String, Value) {
    let context = format!("{kind:?} '{name}'");
    let request = get_observed_request_for_actor(world, name, kind);
    let credential = if kind == TargetActorKind::McpServer {
        mcp_identity_credential(&request.json_body(), &context)
    } else {
        get_a2a_binding_extension(request, &context)
    };
    let vp = &credential["verifiablePresentation"];
    assert!(is_valid_vp(vp), "{context} should receive a valid identity presentation, got: {vp}");
    let subject = first_credential_subject_from_vp(vp);
    (get_holder_did_from_vp(vp), subject["identityFields"].clone())
}

async fn destination_received_vp_proving_key_did(
    world: &mut SurfaceWorld,
    name: &str,
    kind: TargetActorKind,
    key: &str,
) {
    let (did, fields) = received_identity_presentation(world, name, kind);
    assert_eq!(
        fields,
        json!({ "credential_type": "api_key", "api_key_id": key_id(key) }),
        "{kind:?} '{name}' should receive the identity of key '{key}' ({did}), got identity fields {fields}"
    );
    let issued = issued_did_of_key(world, key).await;
    assert_eq!(did, issued, "{kind:?} '{name}' should receive the DID the gateway issued for key '{key}'");
}

#[then(expr = "external agent {string} received the request with a VP proving the DID of key {string}")]
async fn external_agent_received_vp_proving_key_did(
    world: &mut SurfaceWorld,
    agent: String,
    key: String,
) {
    destination_received_vp_proving_key_did(world, &agent, TargetActorKind::ExternalAgent, &key).await;
}

#[then(expr = "MCP server {string} received the request with a VP proving the DID of key {string}")]
async fn mcp_server_received_vp_proving_key_did(
    world: &mut SurfaceWorld,
    server: String,
    key: String,
) {
    destination_received_vp_proving_key_did(world, &server, TargetActorKind::McpServer, &key).await;
}

#[then(expr = "the DID is not the DID of key {string}")]
async fn the_did_is_not_the_did_of_key(
    world: &mut SurfaceWorld,
    key: String,
) {
    let (agent, kind) = destination(world);
    let (did, _) = received_identity_presentation(world, &agent, kind);
    let issued = issued_did_of_key(world, &key).await;
    if let Some(copied) = world
        .copied_identity_extension
        .as_ref()
    {
        assert_eq!(copied["did"], issued.as_str(), "the copied identity extension should prove the DID of key '{key}'");
    }
    assert_ne!(did, issued, "external agent '{agent}' should not receive the DID of key '{key}'");
}

#[then("both identity presentations prove the same DID")]
fn both_identity_presentations_prove_the_same_did(world: &mut SurfaceWorld) {
    let managed = managed_agent(world);
    let access_point = get_did_from_a2a_binding_request(
        get_observed_request_for_actor(world, &managed, TargetActorKind::ManagedAgent),
        &format!("managed agent '{managed}'"),
    );
    let external = external_agent(world);
    let (transit_point, _) = received_identity_presentation(world, &external, TargetActorKind::ExternalAgent);
    assert_eq!(
        access_point, transit_point,
        "the Access Point's identity presentation to '{managed}' and the Transit Point's to '{external}' should prove the same DID"
    );
}

/// A disabled surface draft with one A2A Transit Point `alias` that authenticates its callers
/// with `source_auth`.
async fn surface_draft_with_transit_point(
    world: &mut SurfaceWorld,
    alias: &str,
    source_auth: Value,
) {
    let mut payload = build_primary_target_surface_payload(world, "/example-draft").await;
    payload["name"] = json!("example-draft");
    payload["status"] = json!("disabled");
    payload["transit"] = json!({ "points": [{
        "id": format!("{alias}-id"), "alias": alias, "name": alias, "protocol": "a2a",
        "target_endpoint": DRAFT_TARGET, "listen_path": format!("/transit/{alias}"),
        "require_transit_token": false,
        "source_auth": source_auth
    }] });
    world.surface_draft = Some(payload);
}

#[given(expr = "a surface draft whose Transit Point {string} authenticates its callers with JWT Bearer")]
async fn surface_draft_with_jwt_transit_point(
    world: &mut SurfaceWorld,
    alias: String,
) {
    let strategy = create_caller_jwt_strategy(world).await;
    let source_auth = json!({
        "type": "jwt_bearer", "jwt_verification_strategy_id": strategy,
        "audiences": [format!("bdd-{alias}-audience")], "forward_header": false
    });
    surface_draft_with_transit_point(world, &alias, source_auth).await;
}

#[given(expr = "a surface draft whose Transit Point {string} authenticates its callers with an API key")]
async fn surface_draft_with_api_key_transit_point(
    world: &mut SurfaceWorld,
    alias: String,
) {
    surface_draft_with_transit_point(world, &alias, api_key_provider_source_auth("agents")).await;
}

#[given(expr = "Transit Point {string} in the draft takes the managed agent's identity from its caller's API key")]
fn draft_transit_point_takes_identity_from_caller_api_key(
    world: &mut SurfaceWorld,
    alias: String,
) {
    let point = draft_transit_point(world, &alias);
    point["managed_identity"] = json!({ "type": "from_api_key" });
    point["identity_injection"] = json!({ "inject_vp": true });
}

#[then(expr = "the admin API error response names Transit Point {string} and its caller authentication")]
fn admin_api_error_names_transit_point_and_caller_authentication(
    world: &mut SurfaceWorld,
    alias: String,
) {
    let identity = match draft_transit_point(world, &alias)["managed_identity"]["type"].as_str() {
        Some("from_jwt_claim") => "From JWT Claims",
        Some("from_mtls") => "From mTLS certificate",
        _ => "From API Key",
    };
    let body = &get_admin_response(world).body;
    assert_json_body_mentions(body, &format!("Transit Point '{alias}'"), "admin API error response");
    assert_json_body_mentions(body, identity, "admin API error response");
    assert_json_body_mentions(body, "caller authentication", "admin API error response");
}

#[given(
    expr = "Transit Point {string} in the draft takes the managed agent's identity from its caller's client certificate"
)]
fn draft_transit_point_takes_identity_from_caller_certificate(
    world: &mut SurfaceWorld,
    alias: String,
) {
    let point = draft_transit_point(world, &alias);
    point["managed_identity"] = json!({ "type": "from_mtls" });
    point["identity_injection"] = json!({ "inject_vp": true });
}

#[given(expr = "Transit Point {string} authenticates its callers by client certificates issued by CA {string}")]
fn transit_point_authenticates_callers_by_client_certificates(
    world: &mut SurfaceWorld,
    transit_point: String,
    ca: String,
) {
    before_the_gateway_starts(world, "the CA that issues the Transit Point callers' certificates");
    let authority = TestCertificateAuthority::generate(&ca);
    let server = MockTls::generate();
    world
        .surface_config
        .outbound_client_certificates = Some(OutboundClientCertificatesFixture {
        ca_id: ca.clone(),
        ca_certificate_pem: authority
            .certificate_pem
            .clone(),
        server_certificate_pem: server.certificate_pem.clone(),
        server_private_key_pem: server.private_key_pem.clone(),
    });
    world.client_certificate_ca = Some(authority);
    world.outbound_listener_tls = Some(server);
    transit_point_config_mut(world, &transit_point).source_auth = Some(json!({
        "type": "mtls",
        "trust": { "type": "ca", "ca_certificate_ids": [ca] },
        "identity_binding": { "type": "subject_cn" },
    }));
}

#[given(expr = "Transit Point {string} takes the managed agent's identity from its caller's client certificate")]
fn transit_point_takes_identity_from_caller_certificate(
    world: &mut SurfaceWorld,
    transit_point: String,
) {
    transit_point_config_mut(world, &transit_point).identity_from_caller_certificate = true;
}

/// Managed agent `agent` sends a message/send request through Transit Point `transit_point`
/// over https, presenting a client certificate for `principal`.
async fn send_with_client_certificate(
    world: &mut SurfaceWorld,
    agent: &str,
    transit_point: &str,
    principal: &str,
) {
    world
        .actors
        .expect_target_kind(agent, TargetActorKind::ManagedAgent);
    ensure_gateway_running(world).await;
    let infra = world
        .infra
        .as_mut()
        .expect("scenario infra must exist");
    let outbound_port = infra.outbound_port;
    infra
        .gateway
        .wait_for_secondary_port(outbound_port, std::time::Duration::from_secs(15))
        .await
        .unwrap_or_else(|error| panic!("outbound listener did not become ready on port {outbound_port}: {error}"));
    let url = format!("https://127.0.0.1:{outbound_port}{}", transit_point_path(world, transit_point));
    let certificate = world
        .client_certificate_ca
        .as_ref()
        .expect("the Transit Point's callers must have a CA")
        .issue_client_certificate(principal);
    let server = world
        .outbound_listener_tls
        .as_ref()
        .expect("the outbound listener must serve https");
    let body = build_a2a_message_send_body("hello");
    world.sent_body = Some(body.clone());
    let response = client_presenting_certificate(server, &certificate)
        .post(&url)
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|error| {
            panic!("sending through Transit Point '{transit_point}' with a certificate for '{principal}': {error:?}")
        });
    record_transit_point_response(world, response).await;
}

/// Checks that the request a Given step sent through Transit Point `transit_point` succeeded.
fn expect_reached(
    world: &SurfaceWorld,
    agent: &str,
    transit_point: &str,
) {
    let status = world
        .caller_response
        .as_ref()
        .map(|response| response.status);
    assert_eq!(status, Some(200), "managed agent '{agent}' must reach Transit Point '{transit_point}' first");
}

#[given(
    expr = "managed agent {string} has sent a request through Transit Point {string} with a client certificate for {string}"
)]
async fn managed_agent_has_sent_request_with_client_certificate(
    world: &mut SurfaceWorld,
    agent: String,
    transit_point: String,
    principal: String,
) {
    send_with_client_certificate(world, &agent, &transit_point, &principal).await;
    expect_reached(world, &agent, &transit_point);
}

#[when(
    regex = r#"^managed agent "([^"]+)" sends an A2A message/send request through Transit Point "([^"]+)" with a client certificate for "([^"]+)"$"#
)]
async fn managed_agent_sends_request_with_client_certificate(
    world: &mut SurfaceWorld,
    agent: String,
    transit_point: String,
    principal: String,
) {
    send_with_client_certificate(world, &agent, &transit_point, &principal).await;
}

#[given(expr = "Transit Point {string} in the draft takes the managed agent's identity from the JWT claim {string}")]
fn draft_transit_point_takes_identity_from_jwt_claim(
    world: &mut SurfaceWorld,
    alias: String,
    claim: String,
) {
    let point = draft_transit_point(world, &alias);
    point["managed_identity"] = json!({ "type": "from_jwt_claim", "claim": claim, "namespace_claims": [] });
    point["identity_injection"] = json!({ "inject_vp": true });
}

#[given(
    expr = "Transit Point {string} in the draft takes the managed agent's identity from the JWT claim {string} namespaced by claim {string}"
)]
fn draft_transit_point_takes_identity_from_namespaced_jwt_claim(
    world: &mut SurfaceWorld,
    alias: String,
    claim: String,
    namespace: String,
) {
    let point = draft_transit_point(world, &alias);
    point["managed_identity"] = json!({ "type": "from_jwt_claim", "claim": claim, "namespace_claims": [namespace] });
    point["identity_injection"] = json!({ "inject_vp": true });
}

#[given(expr = "Transit Point {string} takes the managed agent's identity from the JWT claim {string}")]
fn transit_point_takes_identity_from_jwt_claim(
    world: &mut SurfaceWorld,
    transit_point: String,
    claim: String,
) {
    transit_point_config_mut(world, &transit_point).identity_from_jwt_claim = Some(claim);
}

/// A JWT Bearer token for Transit Point `transit_point`'s audience, signed by the identity
/// provider its caller authentication trusts, whose `claim` is `value`, or without `claim`.
fn transit_point_token(
    world: &mut SurfaceWorld,
    transit_point: &str,
    claim: &str,
    value: Option<&str>,
) -> String {
    let audience = transit_point_config_mut(world, transit_point)
        .source_auth
        .as_ref()
        .and_then(|source_auth| source_auth["audiences"][0].as_str())
        .unwrap_or_else(|| {
            panic!("Transit Point '{transit_point}' must authenticate its callers with JWT Bearer tokens")
        })
        .to_string();
    let issuer = world
        .infra
        .as_ref()
        .and_then(|infra| infra._jwks_server.as_ref())
        .expect("the identity provider of the Transit Point's callers must be running")
        .base_url
        .clone();
    let now = jwt::now_secs();
    let mut claims = json!({
        "iss": issuer, "sub": format!("agent-{}", value.unwrap_or("without-claim")), "aud": [audience],
        "iat": now, "exp": now + 3600,
    });
    if let Some(value) = value {
        claims[claim] = json!(value);
    }
    jwt::sign_jwt(claims)
}

/// Managed agent `agent` sends a message/send request through Transit Point `transit_point`
/// with a JWT Bearer token whose `claim` is `value`, or without `claim`.
async fn send_with_token(
    world: &mut SurfaceWorld,
    agent: &str,
    transit_point: &str,
    claim: &str,
    value: Option<&str>,
) {
    world
        .actors
        .expect_target_kind(agent, TargetActorKind::ManagedAgent);
    ensure_gateway_running(world).await;
    let token = transit_point_token(world, transit_point, claim, value);
    let header = ("Authorization".to_string(), format!("Bearer {token}"));
    send_a2a_body_through_transit_point(
        world,
        agent,
        transit_point,
        vec![header],
        build_a2a_message_send_body("hello"),
    )
    .await;
}

#[given(
    expr = "managed agent {string} has sent a request through Transit Point {string} with a token whose {string} is {string}"
)]
async fn managed_agent_has_sent_request_with_token_claim(
    world: &mut SurfaceWorld,
    agent: String,
    transit_point: String,
    claim: String,
    value: String,
) {
    send_with_token(world, &agent, &transit_point, &claim, Some(&value)).await;
    expect_reached(world, &agent, &transit_point);
}

#[when(
    regex = r#"^managed agent "([^"]+)" sends an A2A message/send request through Transit Point "([^"]+)" with a token whose "([^"]+)" is "([^"]+)"$"#
)]
async fn managed_agent_sends_request_with_token_claim(
    world: &mut SurfaceWorld,
    agent: String,
    transit_point: String,
    claim: String,
    value: String,
) {
    send_with_token(world, &agent, &transit_point, &claim, Some(&value)).await;
}

#[when(
    regex = r#"^managed agent "([^"]+)" sends an A2A message/send request through Transit Point "([^"]+)" with a token without "([^"]+)"$"#
)]
async fn managed_agent_sends_request_with_token_without_claim(
    world: &mut SurfaceWorld,
    agent: String,
    transit_point: String,
    claim: String,
) {
    send_with_token(world, &agent, &transit_point, &claim, None).await;
}

#[then(expr = "external agent {string} received two requests with VPs proving different DIDs")]
fn external_agent_received_two_requests_proving_different_dids(
    world: &mut SurfaceWorld,
    agent: String,
) {
    let context = format!("external agent '{agent}'");
    let requests = get_observed_target_requests(
        get_observed_target_for_actor(world, &agent, TargetActorKind::ExternalAgent),
        &context,
    );
    assert_eq!(requests.len(), 2, "{context} should receive two requests, got {}", requests.len());
    let dids: Vec<String> = requests
        .iter()
        .map(|request| {
            let vp = get_a2a_binding_extension(request, &context)["verifiablePresentation"].clone();
            assert!(is_valid_vp(&vp), "{context} should receive a valid identity presentation, got: {vp}");
            get_holder_did_from_vp(&vp)
        })
        .collect();
    assert_ne!(dids[0], dids[1], "{context} should receive two different DIDs, got {dids:?}");
}
