use cucumber::{given, when};

use crate::bdd_support::actors::{PRIMARY_COLLABORATOR_KEY, SECONDARY_COLLABORATOR_KEY, TargetActorKind};
use crate::bdd_support::admin_client::AdminApiClient;
use crate::bdd_support::caller::{RecordedHttpResponse, post_json};
use crate::bdd_support::config;
use crate::bdd_support::config::single_surface_writer::JwksFiles;
use crate::bdd_support::debug::log_to_file;
use crate::bdd_support::gateway_process::{GatewayProcess, SURFACE_TEST_AUTH_TOKEN as TEST_AUTH_TOKEN};
use crate::bdd_support::http::collect_headers;
use crate::bdd_support::json_rpc::{
    MODERN_MCP_PROTOCOL_VERSION, build_a2a_message_send_body, build_mcp_agent_identity_payload,
    build_mcp_initialize_body, build_mcp_initialized_notification_body, build_mcp_list_tools_body_with_id,
    build_mcp_request_without_method_body, build_mcp_schema_invalid_agent_identity_tool_call_body,
    build_mcp_tool_call_body, build_mcp_tool_call_with_meta, build_mcp_tool_call_without_meta,
    build_modern_mcp_list_tools_body, modern_mcp_request_headers,
};
use crate::bdd_support::jwt::{self, JwksServer};
use crate::bdd_support::mock_server::MockServer;
use crate::bdd_support::temp::{TempDirGuard, create_project_temp_dir};
use crate::world::{
    JwtSourceAuthConfig, RecordedResponse, ScenarioInfra, SurfaceSourceAuthConfig, SurfaceWorld, TargetObservations,
    debug_line, mcp_identity_schema_with_field,
};

async fn read_mock_observation(mock: &MockServer) -> TargetObservations {
    TargetObservations::from_requests(mock.requests().await)
}

pub(crate) async fn record_mock_observation(world: &mut SurfaceWorld) {
    let observations = {
        let infra = world.infra.as_ref().unwrap();
        read_mock_observation(&infra.mock).await
    };

    world.record_primary_observations(observations);
}

pub(crate) async fn record_replacement_mock_observation(world: &mut SurfaceWorld) {
    let replacement_observation = {
        let infra = world.infra.as_ref().unwrap();
        match infra
            .replacement_mock
            .as_ref()
        {
            Some(mock) => Some(read_mock_observation(mock).await),
            None => None,
        }
    };

    if let Some(observations) = replacement_observation {
        world.record_secondary_observations(Some(observations));
    }
}

pub(crate) async fn ensure_gateway_running(world: &mut SurfaceWorld) {
    let need_gateway_setup_with_actors = world
        .actors
        .gateway_instances()
        .values()
        .any(|val| val.fixture.is_some());
    let need_agent_setup_with_actors = world
        .actors
        .targets()
        .values()
        .any(|val| val.fixture.is_some());
    let need_setup_with_actors = need_gateway_setup_with_actors || need_agent_setup_with_actors;

    if need_setup_with_actors {
        let all_gateway_processes_running = world
            .actors
            .gateway_instances()
            .values()
            .all(|val| {
                world
                    .runtimes
                    .gateway_instances
                    .contains_key(&val.key)
            });
        let all_agent_processes_running = world
            .actors
            .targets()
            .values()
            .all(|val| {
                world
                    .runtimes
                    .targets
                    .contains_key(&val.key)
            });

        let need_some_starting = !all_gateway_processes_running || !all_agent_processes_running;

        if need_some_starting {
            setup_bootstrapped(world).await;
        }
        return;
    }

    if world.infra.is_some() {
        return;
    }

    let mock = if let Some(proxy) = &world
        .surface_config
        .a2a_proxy_target
    {
        if proxy.no_answer {
            MockServer::start_direct_line_without_reply().await
        } else {
            MockServer::start_direct_line(
                serde_json::json!({
                    "agent": world
                        .collaborator(PRIMARY_COLLABORATOR_KEY)
                        .name
                        .clone(),
                })
                .to_string(),
            )
            .await
        }
    } else {
        MockServer::start_with_extra_headers(
            world
                .collaborator_target(PRIMARY_COLLABORATOR_KEY)
                .configured_response
                .clone(),
            world
                .surface_config
                .custom_response_headers
                .clone(),
        )
        .await
    };
    let affinidi_well = if world.terms_enabled {
        let mut response = crate::bdd_support::mock_server::MockResponse::json(
            world
                .affinidi_terms_manifest
                .clone(),
        );
        if !world.affinidi_well_available {
            response.status = 503;
        }
        Some(MockServer::start(response).await)
    } else {
        None
    };
    let mut oauth_endpoint_allowlist = Vec::new();
    let oauth_mock = if matches!(
        world
            .surface_config
            .credential_delegation
            .as_ref()
            .map(|delegation| &delegation.provider_kind),
        Some(crate::world::CredentialProviderKind::OAuth2AuthorizationCode)
    ) {
        let response = crate::bdd_support::mock_server::MockResponse::json(serde_json::json!({
            "access_token": "bdd-delegated-access-token",
            "refresh_token": "bdd-delegated-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "calendar.read calendar.write"
        }));
        let mock = MockServer::start(response).await;
        let base_url = mock.url();
        oauth_endpoint_allowlist.push(format!("{base_url}/authorize"));
        oauth_endpoint_allowlist.push(format!("{base_url}/token"));
        world
            .surface_config
            .oauth_provider_base_url = Some(base_url);
        Some(mock)
    } else {
        None
    };

    let (gateway_port, mut port_reservation) = config::reserve_free_port("gateway inbound port");
    if world
        .surface_config
        .credential_delegation
        .is_some()
    {
        let callback_base_url = format!("http://127.0.0.1:{gateway_port}");
        if let Some(delegation) = &world
            .surface_config
            .credential_delegation
        {
            oauth_endpoint_allowlist
                .push(format!("{callback_base_url}/v1/identity/oauth/callback/{}", delegation.provider_id));
        }
        world
            .surface_config
            .oauth_callback_base_url = Some(callback_base_url);
    }
    let replacement_mock = if world
        .surface_config
        .transit_point
        .is_some()
    {
        Some(
            MockServer::start(
                world
                    .collaborator_target(SECONDARY_COLLABORATOR_KEY)
                    .configured_response
                    .clone(),
            )
            .await,
        )
    } else {
        None
    };
    let (outbound_port, mut outbound_port_reservation) = if world
        .surface_config
        .transit_point
        .is_some()
    {
        let (port, reservation) = config::reserve_free_port("gateway outbound port");
        (port, Some(reservation))
    } else {
        (0, None)
    };
    let temp_dir = create_project_temp_dir("surface-bdd-").expect("create surface temp dir");

    let (jwks_server, jwks_files) = if matches!(
        world
            .surface_config
            .source_auth,
        Some(SurfaceSourceAuthConfig::JwtBearer(_))
    ) {
        let jwks_server = JwksServer::start().await;
        let issuer = jwks_server.base_url.clone();

        if let Some(SurfaceSourceAuthConfig::JwtBearer(JwtSourceAuthConfig {
            jwks_url, issuer: auth_issuer, ..
        })) = &mut world
            .surface_config
            .source_auth
        {
            *jwks_url = format!("{}/.well-known/jwks.json", issuer);
            *auth_issuer = issuer.clone();
        }

        (Some(jwks_server), Some(JwksFiles { issuer }))
    } else {
        (None, None)
    };

    if let Some(transit_target_url) = replacement_mock
        .as_ref()
        .map(MockServer::url)
    {
        let transit_target_url = if world.target_is_unreachable(SECONDARY_COLLABORATOR_KEY) {
            "http://127.0.0.1:1".to_string()
        } else {
            transit_target_url
        };
        config::single_surface_writer::write_single_surface_config_with_outbound_listener(
            temp_dir.path(),
            gateway_port,
            outbound_port,
            &mock.url(),
            &transit_target_url,
            &world.surface_config,
            jwks_files.as_ref(),
        );
    } else if world.terms_enabled {
        config::single_surface_writer::write_single_surface_config_with_terms(
            temp_dir.path(),
            gateway_port,
            &mock.url(),
            &format!(
                "{}/terms/v1/current.json",
                affinidi_well
                    .as_ref()
                    .expect("Terms-enabled scenario requires Affinidi Well")
                    .url()
            ),
            &world.surface_config,
            jwks_files.as_ref(),
        );
    } else {
        config::single_surface_writer::write_single_surface_config(
            temp_dir.path(),
            gateway_port,
            &mock.url(),
            &world.surface_config,
            jwks_files.as_ref(),
        );
    }

    if world.affinidi_cache_seeded {
        let cache_dir = temp_dir
            .path()
            .join("_storage/terms/affinidi");
        std::fs::create_dir_all(&cache_dir).expect("Affinidi Terms cache directory should be created");
        std::fs::write(
            cache_dir.join("current.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "id": "current",
                "manifest": world.affinidi_terms_manifest,
                "last_successful_refresh": "2026-09-02T00:00:00Z"
            }))
            .expect("Affinidi Terms cache should serialize"),
        )
        .expect("Affinidi Terms cache should be written");
    }

    let config_path = temp_dir
        .path()
        .join("config.toml");
    port_reservation.release_listener();
    if let Some(reservation) = &mut outbound_port_reservation {
        reservation.release_listener();
    }
    let mut gateway_env = if oauth_endpoint_allowlist.is_empty() {
        std::collections::HashMap::new()
    } else {
        std::collections::HashMap::from([(
            "AG_BDD_OAUTH_ENDPOINT_ALLOWLIST".to_string(),
            oauth_endpoint_allowlist.join(","),
        )])
    };
    if world.terms_enabled {
        gateway_env.insert("AFFINIDI_TERMS_REFRESH_INTERVAL_SECONDS".to_string(), "1".to_string());
    }
    let mut gateway = GatewayProcess::start_surface_with_env(&config_path, temp_dir.path(), &gateway_env);
    gateway = gateway
        .with_port(gateway_port)
        .with_port_reservation(port_reservation);
    gateway
        .wait_until_ready()
        .await;
    if world
        .surface_config
        .transit_point
        .is_some()
    {
        gateway
            .wait_for_secondary_port(outbound_port, std::time::Duration::from_secs(15))
            .await
            .unwrap_or_else(|error| panic!("outbound listener did not become ready on port {outbound_port}: {error}"));
    }
    drop(outbound_port_reservation);

    world.infra = Some(ScenarioInfra {
        _temp_dir: TempDirGuard::new(temp_dir, "surface-bdd"),
        gateway,
        mock,
        replacement_mock: replacement_mock.or(oauth_mock),
        affinidi_well,
        _jwks_server: jwks_server,
        gateway_port,
        outbound_port,
    });
}

pub async fn ensure_admin_session(world: &mut SurfaceWorld) {
    if world.admin_client.is_some() {
        return;
    }

    ensure_gateway_running(world).await;

    let gateway_port = world
        .infra
        .as_ref()
        .expect("scenario infra must exist")
        .gateway_port;
    let client = AdminApiClient::new(gateway_port, TEST_AUTH_TOKEN, "surface-bdd-admin");
    client
        .bootstrap_test_session()
        .await
        .expect("test-support auth login should succeed");
    world.admin_client = Some(client);
}

pub(crate) fn configure_unseeded_route(
    world: &mut SurfaceWorld,
    route: &str,
) {
    configure_unseeded_routes(world, route, &[route]);
}

pub(crate) fn configure_unseeded_routes(
    world: &mut SurfaceWorld,
    primary_route: &str,
    registered_routes: &[&str],
) {
    world.surface_config.route = primary_route.to_string();
    world
        .surface_config
        .registered_routes = registered_routes
        .iter()
        .map(|route| (*route).to_string())
        .collect();
    world
        .surface_config
        .seed_surface = false;
}

fn get_primary_target_url(world: &SurfaceWorld) -> String {
    world
        .infra
        .as_ref()
        .expect("scenario infra must exist")
        .mock
        .url()
}

pub(crate) fn get_alternate_target_url(world: &SurfaceWorld) -> String {
    world
        .infra
        .as_ref()
        .expect("scenario infra must exist")
        .replacement_mock
        .as_ref()
        .expect("alternate mock agent must exist before targeting it")
        .url()
}

pub(crate) async fn build_primary_target_surface_payload(
    world: &mut SurfaceWorld,
    route: &str,
) -> serde_json::Value {
    ensure_admin_session(world).await;
    let target_url = get_primary_target_url(world);
    build_surface_payload(world, route, &target_url)
}

pub(crate) fn build_surface_payload(
    world: &SurfaceWorld,
    route: &str,
    target_url: &str,
) -> serde_json::Value {
    let infra = world
        .infra
        .as_ref()
        .expect("scenario infra must exist");

    let surface_name = world
        .surface_config
        .surface_name
        .as_deref()
        .unwrap_or("bdd-created-surface");

    serde_json::json!({
        "name": surface_name,
        "description": "BDD-created surface",
        "status": "active",
        "access_point": {
            "listen_address": format!("http://localhost:{}", infra.gateway_port),
            "route": route,
            "protocol": world.surface_config.protocol,
        },
        "target": {
            "endpoint": target_url,
        }
    })
}

fn record_caller_response(
    world: &mut SurfaceWorld,
    response: RecordedHttpResponse,
) {
    world.caller_response = Some(RecordedResponse {
        status: response.status,
        headers: response.headers,
        body: response.body,
    });
}

fn record_admin_response(
    world: &mut SurfaceWorld,
    response: crate::world::RecordedResponse,
) {
    if let Some(surface_id) = response
        .body
        .get("surface_id")
        .and_then(|value| value.as_str())
    {
        world.created_surface_id = Some(surface_id.to_string());
    }

    world.admin_response = Some(response);
}

pub(crate) async fn create_surface(
    world: &mut SurfaceWorld,
    payload: serde_json::Value,
) {
    ensure_admin_session(world).await;

    let client = world
        .admin_client
        .as_ref()
        .expect("admin client must exist");
    let response = client
        .create_surface_recorded(&payload)
        .await
        .expect("create surface through admin API");

    record_admin_response(world, response);
}

pub(crate) async fn fetch_surface_by_id(
    world: &mut SurfaceWorld,
    surface_id: &str,
) {
    ensure_admin_session(world).await;

    let client = world
        .admin_client
        .as_ref()
        .expect("admin client must exist");
    let response = client
        .get_surface_recorded(surface_id)
        .await
        .expect("fetch surface by id");

    world.surface_lookup_response = Some(response);
}

fn get_tracked_surface_id(
    world: &SurfaceWorld,
    action: &str,
) -> String {
    world
        .surface_under_test_id
        .clone()
        .or_else(|| {
            world
                .created_surface_id
                .clone()
        })
        .unwrap_or_else(|| panic!("surface id must be set before {}", action))
}

fn get_current_admin_surface_body(
    world: &SurfaceWorld,
    action: &str,
) -> serde_json::Value {
    world
        .admin_response
        .as_ref()
        .unwrap_or_else(|| panic!("admin_response must contain the existing surface before {}", action))
        .body
        .clone()
}

async fn update_created_surface(
    world: &mut SurfaceWorld,
    payload: serde_json::Value,
    action: &str,
) {
    ensure_admin_session(world).await;
    let surface_id = get_tracked_surface_id(world, action);

    let client = world
        .admin_client
        .as_ref()
        .expect("admin client must exist");
    let response = client
        .update_surface_recorded(&surface_id, &payload)
        .await
        .unwrap_or_else(|error| panic!("{action} through admin API: {error}"));

    record_admin_response(world, response);
}

async fn fetch_created_surface(
    world: &mut SurfaceWorld,
    action: &str,
) {
    let surface_id = get_tracked_surface_id(world, action);
    fetch_surface_by_id(world, &surface_id).await;
}

fn build_request_body(protocol: &str) -> serde_json::Value {
    match protocol {
        "a2a" => build_a2a_message_send_body("hello"),
        "mcp" => build_mcp_list_tools_body_with_id(serde_json::json!("mcp-tools-list-alpha")),
        other => panic!("unsupported surface protocol for request step: {}", other),
    }
}

async fn send_json_request_to_path_and_record(
    world: &mut SurfaceWorld,
    path_and_query: &str,
    body: serde_json::Value,
    headers: Vec<(String, String)>,
) {
    ensure_gateway_running(world).await;

    let infra = world.infra.as_ref().unwrap();
    let url = format!("http://127.0.0.1:{}{}", infra.gateway_port, path_and_query);

    world.sent_body = Some(body.clone());

    let client = reqwest::Client::new();
    let response = post_json(&client, &url, &body, &headers)
        .await
        .expect("send request to gateway");

    record_caller_response(world, response);

    record_mock_observation(world).await;
    record_replacement_mock_observation(world).await;
}

async fn send_raw_string_request_and_record(
    world: &mut SurfaceWorld,
    raw_body: &str,
    content_type: &str,
) {
    ensure_gateway_running(world).await;

    let infra = world.infra.as_ref().unwrap();
    let url = format!("http://127.0.0.1:{}{}/foo", infra.gateway_port, world.surface_config.route);

    world.sent_body = None;

    let resp = reqwest::Client::new()
        .post(&url)
        .header("content-type", content_type)
        .body(raw_body.to_string())
        .send()
        .await
        .expect("send raw request to gateway");

    let status = resp.status().as_u16();
    let headers = collect_headers(resp.headers());
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or(serde_json::Value::Null);

    world.caller_response = Some(RecordedResponse { status, headers, body });

    record_mock_observation(world).await;
    record_replacement_mock_observation(world).await;
}

async fn send_request_to_path_and_record(
    world: &mut SurfaceWorld,
    path_and_query: &str,
    headers: Vec<(String, String)>,
) {
    let body = build_request_body(&world.surface_config.protocol);
    send_json_request_to_path_and_record(world, path_and_query, body, headers).await;
}

async fn send_json_request_and_record(
    world: &mut SurfaceWorld,
    body: serde_json::Value,
    headers: Vec<(String, String)>,
) {
    let path = format!("{}/foo", world.surface_config.route);
    send_json_request_to_path_and_record(world, &path, body, headers).await;
}

fn build_a2a_message_send_body_with_parts(parts: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": "bdd-a2a-proxy-request",
        "method": "message/send",
        "params": {
            "message": {
                "kind": "message",
                "role": "user",
                "messageId": "bdd-message",
                "contextId": "bdd-context",
                "parts": parts,
            }
        }
    })
}

/// Send an A2A request to an A2A-proxy surface. Such a surface serves A2A 1.0
/// only, so the request negotiates 1.0 unless the scenario sets `A2A-Version`
/// itself.
async fn send_a2a_proxy_request_and_record(
    world: &mut SurfaceWorld,
    body: serde_json::Value,
    mut headers: Vec<(String, String)>,
) {
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("A2A-Version"))
    {
        headers.push(("A2A-Version".to_string(), "1.0".to_string()));
    }
    send_a2a_proxy_request_without_version_and_record(world, body, headers).await;
}

async fn send_a2a_proxy_request_without_version_and_record(
    world: &mut SurfaceWorld,
    body: serde_json::Value,
    headers: Vec<(String, String)>,
) {
    let path = format!("{}/rpc", world.surface_config.route);
    send_json_request_to_path_and_record(world, &path, body, headers).await;
}

#[when(expr = "the caller sends an A2A message\\/send request to surface {string} without an A2A-Version header")]
async fn caller_sends_a2a_message_send_without_version(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "unknown surface '{surface_name}'"
    );
    let body = build_a2a_message_send_body_with_parts(vec![serde_json::json!({ "kind": "text", "text": "hello" })]);
    send_a2a_proxy_request_without_version_and_record(world, body, Vec::new()).await;
}

#[when(expr = "the caller fetches the agent card for surface {string}")]
async fn caller_fetches_agent_card_for_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "unknown surface '{surface_name}'"
    );
    ensure_gateway_running(world).await;
    let infra = world
        .infra
        .as_ref()
        .expect("gateway infra must be running");
    let url =
        format!("http://127.0.0.1:{}{}/.well-known/agent-card.json", infra.gateway_port, world.surface_config.route);
    let response = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("fetch agent card through gateway");
    let status = response.status().as_u16();
    let headers = collect_headers(response.headers());
    let content_type = headers
        .get("content-type")
        .cloned();
    let body = response
        .json()
        .await
        .expect("agent card response should be JSON");
    record_caller_response(
        world,
        RecordedHttpResponse {
            status,
            headers,
            body,
            content_type,
        },
    );
    record_mock_observation(world).await;
    record_replacement_mock_observation(world).await;
}

#[when(regex = r#"^the caller sends an A2A message/send request to surface "([^"]+)" with mapped identity headers$"#)]
async fn caller_sends_a2a_message_send_with_mapped_identity_headers(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "unknown surface '{surface_name}'"
    );
    let body = build_a2a_message_send_body_with_parts(vec![serde_json::json!({ "kind": "text", "text": "hello" })]);
    send_a2a_proxy_request_and_record(
        world,
        body,
        vec![
            ("x-agent-id".to_string(), "agent-123".to_string()),
            ("x-tenant-id".to_string(), "tenant-456".to_string()),
        ],
    )
    .await;
}

#[when(
    regex = r#"^the caller sends an A2A message/send request to surface "([^"]+)" with header "([^"]+)" set to "([^"]+)"$"#
)]
async fn caller_sends_a2a_message_send_with_header(
    world: &mut SurfaceWorld,
    surface_name: String,
    header_name: String,
    header_value: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "unknown surface '{surface_name}'"
    );
    let body = build_a2a_message_send_body_with_parts(vec![serde_json::json!({ "kind": "text", "text": "hello" })]);
    send_a2a_proxy_request_and_record(world, body, vec![(header_name, header_value)]).await;
}

#[when(regex = r#"^the caller sends an A2A message/send request to surface "([^"]+)" without header "([^"]+)"$"#)]
async fn caller_sends_a2a_message_send_without_header(
    world: &mut SurfaceWorld,
    surface_name: String,
    header_name: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "unknown surface '{surface_name}'"
    );
    let body = build_a2a_message_send_body_with_parts(vec![serde_json::json!({ "kind": "text", "text": "hello" })]);
    let other_header = format!("{header_name}-other");
    send_a2a_proxy_request_and_record(world, body, vec![(other_header, "not-mapped".to_string())]).await;
}

async fn send_a2a_message_with_valid_api_key_and_headers(
    world: &mut SurfaceWorld,
    headers: Vec<(String, String)>,
) {
    let body = build_a2a_message_send_body_with_parts(vec![serde_json::json!({ "kind": "text", "text": "hello" })]);
    let mut all_headers = vec![build_valid_api_key_source_auth_header(world)];
    all_headers.extend(headers);
    send_a2a_proxy_request_and_record(world, body, all_headers).await;
}

async fn send_a2a_message_with_valid_api_key_and_identity_headers(
    world: &mut SurfaceWorld,
    agent_id: String,
    tenant_id: String,
) {
    send_a2a_message_with_valid_api_key_and_headers(
        world,
        vec![("x-agent-id".to_string(), agent_id), ("x-tenant-id".to_string(), tenant_id)],
    )
    .await;
}

async fn caller_sends_a2a_message_send_with_valid_api_key_and_mapped_identity_headers(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "unknown surface '{surface_name}'"
    );
    send_a2a_message_with_valid_api_key_and_identity_headers(world, "agent-123".to_string(), "tenant-456".to_string())
        .await;
}

#[given(
    regex = r#"^the caller has sent an A2A message/send request to surface "([^"]+)" with a valid API key and mapped identity headers$"#
)]
async fn caller_has_sent_a2a_message_send_with_valid_api_key_and_mapped_identity_headers(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    caller_sends_a2a_message_send_with_valid_api_key_and_mapped_identity_headers(world, surface_name).await;
}

#[when(
    regex = r#"^the caller sends an A2A message/send request to surface "([^"]+)" with a valid API key and mapped identity headers for agent "([^"]+)" and tenant "([^"]+)"$"#
)]
async fn caller_sends_a2a_message_send_with_valid_api_key_and_named_identity_headers(
    world: &mut SurfaceWorld,
    surface_name: String,
    agent_id: String,
    tenant_id: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "unknown surface '{surface_name}'"
    );
    send_a2a_message_with_valid_api_key_and_identity_headers(world, agent_id, tenant_id).await;
}

#[when(
    regex = r#"^the caller sends an A2A message/send request to surface "([^"]+)" with correlation header "([^"]+)"$"#
)]
async fn caller_sends_a2a_message_send_with_correlation_header(
    world: &mut SurfaceWorld,
    surface_name: String,
    correlation: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "unknown surface '{surface_name}'"
    );
    send_a2a_message_with_valid_api_key_and_headers(
        world,
        vec![
            ("x-agent-id".to_string(), "agent-123".to_string()),
            ("x-tenant-id".to_string(), "tenant-456".to_string()),
            ("x-correlation-id".to_string(), correlation),
        ],
    )
    .await;
}

#[given(
    regex = r#"^the caller has sent an A2A message/send request to surface "([^"]+)" with correlation header "([^"]+)"$"#
)]
async fn caller_has_sent_a2a_message_send_with_correlation_header(
    world: &mut SurfaceWorld,
    surface_name: String,
    correlation: String,
) {
    caller_sends_a2a_message_send_with_correlation_header(world, surface_name, correlation).await;
}

#[when(
    regex = r#"^the caller sends an A2A message/send request to surface "([^"]+)" with a valid API key and header "([^"]+)" set to "([^"]+)"$"#
)]
async fn caller_sends_a2a_message_send_with_valid_api_key_and_header(
    world: &mut SurfaceWorld,
    surface_name: String,
    header_name: String,
    header_value: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "unknown surface '{surface_name}'"
    );
    let body = build_a2a_message_send_body_with_parts(vec![serde_json::json!({ "kind": "text", "text": "hello" })]);
    let api_key_header = build_valid_api_key_source_auth_header(world);
    send_a2a_proxy_request_and_record(world, body, vec![api_key_header, (header_name, header_value)]).await;
}

#[when(
    expr = "the operator attempts to create an MCP Transit Point mapping managed-agent header {string} to A2A metadata field {string}"
)]
async fn operator_attempts_create_mcp_transit_point_with_header_metadata_mapping(
    world: &mut SurfaceWorld,
    header_name: String,
    field: String,
) {
    let route = world
        .surface_config
        .route
        .clone();
    world.surface_config.protocol = "a2a".to_string();
    let mut payload = build_primary_target_surface_payload(world, &route).await;
    payload["transit"] = serde_json::json!({
        "outbound_listen_address": format!(
            "http://localhost:{}",
            world
                .infra
                .as_ref()
                .expect("scenario infra must exist")
                .gateway_port
        ),
        "points": [{
            "name": "tr1",
            "alias": "tr1",
            "target_endpoint": "http://example.invalid/mcp",
            "protocol": "mcp",
            "listen_path": "/transit/tr1",
            "require_transit_token": false,
            "header_metadata_mapping": {
                "extension_uri": "https://fabric.affinidi.io/extensions/header-metadata/v1",
                "headers": [{
                    "header": header_name,
                    "field": field,
                }],
            }
        }]
    });
    create_surface(world, payload).await;
}

#[when(
    expr = "the operator attempts to create an A2A surface for route {string} mapping inbound header {string} to A2A metadata field {string}"
)]
async fn operator_attempts_create_a2a_surface_with_header_metadata_mapping(
    world: &mut SurfaceWorld,
    route: String,
    header_name: String,
    field: String,
) {
    configure_unseeded_route(world, &route);
    world.surface_config.protocol = "a2a".to_string();
    let mut payload = build_primary_target_surface_payload(world, &route).await;
    payload["access_point"]["header_metadata_mapping"] = serde_json::json!({
        "headers": [{
            "header": header_name,
            "field": field,
        }],
    });
    create_surface(world, payload).await;
}

#[when(expr = "the caller sends an A2A message/send request to surface {string} with text {string}")]
async fn caller_sends_a2a_message_send_with_text(
    world: &mut SurfaceWorld,
    surface_name: String,
    text: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "unknown surface '{surface_name}'"
    );
    let body = build_a2a_message_send_body_with_parts(vec![serde_json::json!({ "kind": "text", "text": text })]);
    send_a2a_proxy_request_and_record(world, body, Vec::new()).await;
}

#[when(expr = "the caller sends an A2A message/send request to surface {string} with text parts {string} and {string}")]
async fn caller_sends_a2a_message_send_with_text_parts(
    world: &mut SurfaceWorld,
    surface_name: String,
    first: String,
    second: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "unknown surface '{surface_name}'"
    );
    let body = build_a2a_message_send_body_with_parts(vec![
        serde_json::json!({ "kind": "text", "text": first }),
        serde_json::json!({ "kind": "text", "text": second }),
    ]);
    send_a2a_proxy_request_and_record(world, body, Vec::new()).await;
}

#[when(expr = "the caller sends an A2A message/send request to surface {string} with a non-text part")]
async fn caller_sends_a2a_message_send_with_non_text_part(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "unknown surface '{surface_name}'"
    );
    let body = build_a2a_message_send_body_with_parts(vec![serde_json::json!({
        "kind": "file",
        "file": { "name": "example.txt" }
    })]);
    send_a2a_proxy_request_and_record(world, body, Vec::new()).await;
}

/// Swap in the params an A2A method actually requires, so a scenario about a
/// method being refused is not tripped by request-shape validation first. The
/// task methods carry an id rather than a message; everything else keeps the
/// message body the builder produced.
fn set_params_for_method(
    body: &mut serde_json::Value,
    method: &str,
) {
    if matches!(
        method,
        "tasks/get" | "GetTask" | "tasks/cancel" | "CancelTask" | "tasks/resubscribe" | "SubscribeToTask"
    ) {
        body["params"] = serde_json::json!({ "id": "task-1" });
    }
}

#[when(expr = "the caller sends A2A method {string} to surface {string}")]
async fn caller_sends_a2a_method_to_surface(
    world: &mut SurfaceWorld,
    method: String,
    surface_name: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "unknown surface '{surface_name}'"
    );
    let mut body = build_a2a_message_send_body_with_parts(vec![serde_json::json!({ "kind": "text", "text": "hello" })]);
    body["method"] = serde_json::json!(method);
    set_params_for_method(&mut body, &method);
    send_a2a_proxy_request_and_record(world, body, Vec::new()).await;
}

#[when(
    expr = "the caller sends an A2A message/send request to surface {string} with text {string} and header {string} set to {string}"
)]
async fn caller_sends_a2a_message_send_with_text_and_header(
    world: &mut SurfaceWorld,
    surface_name: String,
    text: String,
    header_name: String,
    header_value: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "unknown surface '{surface_name}'"
    );
    let body = build_a2a_message_send_body_with_parts(vec![serde_json::json!({ "kind": "text", "text": text })]);
    send_a2a_proxy_request_and_record(world, body, vec![(header_name, header_value)]).await;
}

async fn send_legacy_sse_tool_call_and_record(
    world: &mut SurfaceWorld,
    body: serde_json::Value,
) {
    ensure_gateway_running(world).await;

    let infra = world.infra.as_ref().unwrap();
    let gateway_base = format!("http://127.0.0.1:{}", infra.gateway_port);
    let route = world
        .surface_config
        .route
        .clone();

    world.sent_body = Some(body.clone());

    let parsed = crate::bdd_support::sse_client::legacy_sse_tool_call(&gateway_base, &route, &body)
        .await
        .expect("legacy SSE tool call should produce a parsed JSON-RPC payload");

    world.caller_response = Some(RecordedResponse {
        status: 200,
        headers: std::collections::HashMap::new(),
        body: parsed,
    });

    record_mock_observation(world).await;
    record_replacement_mock_observation(world).await;
}

async fn send_raw_request_and_record(
    world: &mut SurfaceWorld,
    body: serde_json::Value,
    content_type: &str,
) {
    ensure_gateway_running(world).await;

    let infra = world.infra.as_ref().unwrap();
    let url = format!("http://127.0.0.1:{}{}/foo", infra.gateway_port, world.surface_config.route);

    world.sent_body = Some(body.clone());
    let raw_body = serde_json::to_vec(&body).expect("serialize raw request body");

    let resp = reqwest::Client::new()
        .post(&url)
        .header("content-type", content_type)
        .body(raw_body)
        .send()
        .await
        .expect("send raw request to gateway");

    let status = resp.status().as_u16();
    let headers = collect_headers(resp.headers());
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or(serde_json::Value::Null);

    world.caller_response = Some(RecordedResponse { status, headers, body });

    record_mock_observation(world).await;
    record_replacement_mock_observation(world).await;
}

async fn send_request_and_record(
    world: &mut SurfaceWorld,
    headers: Vec<(String, String)>,
) {
    let body = build_request_body(&world.surface_config.protocol);
    send_json_request_and_record(world, body, headers).await;
}

pub(crate) async fn create_valid_surface_for_route(
    world: &mut SurfaceWorld,
    route: &str,
) {
    configure_unseeded_route(world, route);

    let payload = build_primary_target_surface_payload(world, route).await;

    create_surface(world, payload).await;
}

pub(crate) async fn attempt_invalid_surface_create_for_route(
    world: &mut SurfaceWorld,
    route: &str,
) {
    configure_unseeded_route(world, route);

    let mut payload = build_primary_target_surface_payload(world, route).await;
    payload["target"]["endpoint"] = serde_json::Value::String(String::new());

    create_surface(world, payload).await;
}

pub(crate) async fn update_surface_to_alternate_target(world: &mut SurfaceWorld) {
    let mut payload = get_current_admin_surface_body(world, "updating the surface");
    payload["target"]["endpoint"] = serde_json::Value::String(get_alternate_target_url(world));

    update_created_surface(world, payload, "updating the surface").await;
}

pub(crate) async fn disable_surface(world: &mut SurfaceWorld) {
    let mut payload = get_current_admin_surface_body(world, "disabling the surface");
    payload["status"] = serde_json::Value::String("disabled".to_string());

    update_created_surface(world, payload, "disabling the surface").await;
}

pub async fn update_transit_point_listen_path(
    world: &mut SurfaceWorld,
    transit_point: &str,
    new_path: &str,
) {
    ensure_admin_session(world).await;
    let surface_id = get_tracked_surface_id(world, "updating the Transit Point listen_path");

    let client = world
        .admin_client
        .as_ref()
        .expect("admin client must exist");
    let current = client
        .get_surface_recorded(&surface_id)
        .await
        .unwrap_or_else(|error| panic!("fetch surface before updating Transit Point listen_path: {error}"));
    assert_eq!(
        current.status, 200,
        "fetch surface before updating Transit Point listen_path should succeed, got status {} body {}",
        current.status, current.body
    );

    let mut payload = current.body;
    let points = payload
        .get_mut("transit")
        .and_then(|transit| transit.get_mut("points"))
        .and_then(|points| points.as_array_mut())
        .unwrap_or_else(|| panic!("surface '{}' must include transit.points before updating listen_path", surface_id));
    let point = points
        .iter_mut()
        .find(|point| {
            point
                .get("alias")
                .and_then(|value| value.as_str())
                == Some(transit_point)
                || point
                    .get("name")
                    .and_then(|value| value.as_str())
                    == Some(transit_point)
        })
        .unwrap_or_else(|| {
            panic!("surface '{}' has no Transit Point named or aliased '{}'", surface_id, transit_point)
        });
    point["listen_path"] = serde_json::json!(new_path);

    let response = client
        .update_surface_recorded(&surface_id, &payload)
        .await
        .unwrap_or_else(|error| panic!("update Transit Point listen_path through admin API: {error}"));

    assert_eq!(
        response.status, 200,
        "updating Transit Point listen_path should succeed, got status {} body {}",
        response.status, response.body
    );

    record_admin_response(world, response);
}

pub(crate) async fn delete_surface(world: &mut SurfaceWorld) {
    ensure_admin_session(world).await;
    let surface_id = get_tracked_surface_id(world, "deleting the surface");

    let client = world
        .admin_client
        .as_ref()
        .expect("admin client must exist");
    let response = client
        .delete_surface_recorded(&surface_id)
        .await
        .expect("delete surface through admin API");

    record_admin_response(world, response);
}

pub(crate) async fn read_surface_through_admin_api(world: &mut SurfaceWorld) {
    fetch_created_surface(world, "reading the surface through the admin API").await;
}

#[when(expr = "the operator creates a valid surface for route {string}")]
async fn valid_surface_create_request_submitted(
    world: &mut SurfaceWorld,
    route: String,
) {
    create_valid_surface_for_route(world, &route).await;
}

#[when(expr = "the operator attempts to create an A2A surface for route {string} that accepts no A2A versions")]
async fn surface_without_a2a_versions_create_request_submitted(
    world: &mut SurfaceWorld,
    route: String,
) {
    configure_unseeded_route(world, &route);
    let mut payload = build_primary_target_surface_payload(world, &route).await;
    payload["access_point"]["a2a"] = serde_json::json!({ "accepted_versions": [] });
    create_surface(world, payload).await;
}

#[when(expr = "the operator attempts to create a surface for route {string} with invalid configuration")]
async fn invalid_surface_create_request_submitted(
    world: &mut SurfaceWorld,
    route: String,
) {
    attempt_invalid_surface_create_for_route(world, &route).await;
}

#[when("the operator reads the delegation audit trail")]
async fn operator_reads_delegation_audit_trail(world: &mut SurfaceWorld) {
    read_delegation_audit_trail(world).await;
}

#[when(expr = "operator {string} reads the VP Audit Log")]
async fn operator_reads_vp_audit_log(
    world: &mut SurfaceWorld,
    operator: String,
) {
    read_audit_log_as_operator(world, &operator, "/v1/audit?limit=100").await;
}

#[when(expr = "administrator {string} reads the VP Audit Log")]
async fn administrator_reads_vp_audit_log(
    world: &mut SurfaceWorld,
    operator: String,
) {
    read_audit_log_as_operator(world, &operator, "/v1/audit?limit=100").await;
}

#[when(expr = "operator {string} reads the Credential Delegation Audit Log")]
async fn operator_reads_credential_delegation_audit_log(
    world: &mut SurfaceWorld,
    operator: String,
) {
    read_audit_log_as_operator(world, &operator, "/v1/delegation-audit?page_size=100").await;
}

#[when(expr = "administrator {string} reads the Credential Delegation Audit Log")]
async fn administrator_reads_credential_delegation_audit_log(
    world: &mut SurfaceWorld,
    operator: String,
) {
    read_audit_log_as_operator(world, &operator, "/v1/delegation-audit?page_size=100").await;
}

#[when(expr = "operator {string} asks for their permissions")]
async fn operator_asks_for_permissions(
    world: &mut SurfaceWorld,
    operator: String,
) {
    read_audit_log_as_operator(world, &operator, "/v1/permissions").await;
}

async fn read_audit_log_as_operator(
    world: &mut SurfaceWorld,
    operator: &str,
    path: &str,
) {
    let client = world
        .operator_clients
        .get(operator)
        .unwrap_or_else(|| panic!("operator '{operator}' must have an authenticated role before reading {path}"))
        .clone();
    let response = client
        .send_recorded_json::<serde_json::Value>(reqwest::Method::GET, path, None)
        .await
        .expect("audit or permissions read should return an HTTP response");

    record_admin_response(world, response);
}

pub(crate) async fn read_delegation_audit_trail(world: &mut SurfaceWorld) {
    ensure_admin_session(world).await;

    let client = world
        .admin_client
        .as_ref()
        .expect("admin client must exist");
    let mut response = client
        .send_recorded_json::<serde_json::Value>(reqwest::Method::GET, "/v1/delegation-audit?page_size=100", None)
        .await
        .expect("read delegation audit trail through admin API");

    for _ in 0..10 {
        let has_events = response
            .body
            .get("events")
            .and_then(|events| events.as_array())
            .is_some_and(|events| !events.is_empty());
        if has_events {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        response = client
            .send_recorded_json::<serde_json::Value>(reqwest::Method::GET, "/v1/delegation-audit?page_size=100", None)
            .await
            .expect("read delegation audit trail through admin API");
    }

    record_admin_response(world, response);
}

#[when("the operator reads the surface through the admin API")]
async fn operator_reads_surface_through_admin_api(world: &mut SurfaceWorld) {
    read_surface_through_admin_api(world).await;
}

#[when(expr = "the caller sends a request to the surface path {string}")]
async fn request_sent_to_surface_path(
    world: &mut SurfaceWorld,
    path: String,
) {
    send_request_to_path_and_record(world, &path, vec![]).await;
}

#[when("the caller fetches the gateway DID document")]
async fn gateway_did_document_fetched(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;

    let infra = world
        .infra
        .as_ref()
        .expect("scenario infra must exist");
    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/.well-known/did.json", infra.gateway_port))
        .send()
        .await
        .expect("fetch gateway DID document");

    world.sent_body = None;
    let status = response.status().as_u16();
    let headers = collect_headers(response.headers());
    let body = response
        .json()
        .await
        .unwrap_or(serde_json::Value::Null);
    world.caller_response = Some(RecordedResponse { status, headers, body });

    record_mock_observation(world).await;
    record_replacement_mock_observation(world).await;
}

#[when("the caller sends a request to the surface")]
async fn request_sent_to_surface(world: &mut SurfaceWorld) {
    send_request_and_record(world, vec![]).await;
}

#[when("the caller sends a request to the surface without a token")]
async fn request_without_token(world: &mut SurfaceWorld) {
    send_request_and_record(world, vec![]).await;
}

fn get_jwt_source_auth_issuer(world: &SurfaceWorld) -> String {
    world
        .surface_config
        .source_auth
        .as_ref()
        .and_then(|auth| match auth {
            SurfaceSourceAuthConfig::JwtBearer(JwtSourceAuthConfig { issuer, .. }) => Some(issuer.clone()),
            _ => None,
        })
        .expect("jwt source_auth must be configured")
}

fn create_expired_jwt_for_issuer(issuer: String) -> String {
    let now = jwt::now_secs();
    let claims = serde_json::json!({
        "iss": issuer,
        "sub": "test-user",
        "aud": [],
        "iat": now - 7200,
        "exp": now - 3600
    });
    jwt::sign_jwt(claims)
}

fn create_valid_jwt_for_issuer(issuer: String) -> String {
    create_valid_jwt_for_subject(issuer, "test-user", serde_json::json!({}))
}

fn create_valid_jwt_for_subject(
    issuer: String,
    subject: &str,
    extra_claims: serde_json::Value,
) -> String {
    let now = jwt::now_secs();
    let mut claims = serde_json::json!({
        "iss": issuer,
        "sub": subject,
        "aud": [],
        "iat": now,
        "exp": now + 3600
    });
    if let Some(extra) = extra_claims.as_object()
        && let Some(target) = claims.as_object_mut()
    {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
    jwt::sign_jwt(claims)
}

fn create_valid_jwt_for_subject_with_world_claims(
    world: &SurfaceWorld,
    subject: &str,
    extra_claims: serde_json::Value,
) -> String {
    let mut merged = world
        .caller_claims
        .get(subject)
        .cloned()
        .unwrap_or_default();
    if let Some(extra) = extra_claims.as_object() {
        for (key, value) in extra {
            merged.insert(key.clone(), value.clone());
        }
    }
    create_valid_jwt_for_subject(get_jwt_source_auth_issuer(world), subject, serde_json::Value::Object(merged))
}

fn create_valid_jwt_for_issuer_with_audience(
    issuer: String,
    audience: serde_json::Value,
) -> String {
    let now = jwt::now_secs();
    let claims = serde_json::json!({
        "iss": issuer,
        "sub": "test-user",
        "aud": audience,
        "iat": now,
        "exp": now + 3600
    });
    jwt::sign_jwt(claims)
}

fn create_tampered_jwt_for_issuer(issuer: String) -> String {
    let mut token = create_valid_jwt_for_issuer(issuer);
    let replacement = if token.ends_with('A') {
        'B'
    } else {
        'A'
    };
    token.pop();
    token.push(replacement);
    token
}

async fn send_request_with_bearer_token(
    world: &mut SurfaceWorld,
    token: String,
) {
    send_request_and_record(world, vec![("authorization".to_string(), format!("Bearer {}", token))]).await;
}

#[when("the caller sends a request to the surface with an expired token")]
async fn request_with_expired_token(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let token = create_expired_jwt_for_issuer(get_jwt_source_auth_issuer(world));
    send_request_with_bearer_token(world, token).await;
}

#[when("the caller sends a request to the surface with a malformed token")]
async fn request_with_malformed_token(world: &mut SurfaceWorld) {
    send_request_with_bearer_token(world, "not-a-jwt".to_string()).await;
}

#[when("the caller sends a request to the surface with a tampered token")]
async fn request_with_tampered_token(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let token = create_tampered_jwt_for_issuer(get_jwt_source_auth_issuer(world));
    send_request_with_bearer_token(world, token).await;
}

#[when("the caller sends a request to the surface with a valid token")]
async fn request_with_valid_token(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let token = create_valid_jwt_for_issuer(get_jwt_source_auth_issuer(world));
    send_request_with_bearer_token(world, token).await;
}

const AGENT_IDENTITY_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity/v1";
const AGENT_IDENTITY_CREDENTIAL_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity-credential/v1";

#[when("the caller sends a request to the surface without an API key")]
async fn request_without_api_key(world: &mut SurfaceWorld) {
    send_request_and_record(world, vec![]).await;
}

fn build_api_key_source_auth_header(
    world: &SurfaceWorld,
    key_value: String,
) -> (String, String) {
    let header_name = world
        .surface_config
        .source_auth
        .as_ref()
        .map(|auth| match auth {
            SurfaceSourceAuthConfig::ApiKey(config) => config.header_name.clone(),
            SurfaceSourceAuthConfig::ApiKeyProvider(config) => config.header_name.clone(),
            SurfaceSourceAuthConfig::JwtBearer(_) => panic!("api key source_auth must be configured"),
        })
        .expect("api key source_auth must be configured");

    (header_name, key_value)
}

fn build_valid_api_key_source_auth_header(world: &SurfaceWorld) -> (String, String) {
    let (header_name, valid_key) = world
        .surface_config
        .source_auth
        .as_ref()
        .map(|auth| match auth {
            SurfaceSourceAuthConfig::ApiKey(config) => (config.header_name.clone(), config.valid_key.clone()),
            SurfaceSourceAuthConfig::ApiKeyProvider(config) => (config.header_name.clone(), config.valid_key.clone()),
            SurfaceSourceAuthConfig::JwtBearer(_) => panic!("api key source_auth must be configured"),
        })
        .expect("api key source_auth must be configured");

    (header_name, valid_key)
}

#[when("the caller sends a request to the surface with an invalid API key")]
async fn request_with_invalid_api_key(world: &mut SurfaceWorld) {
    let header = build_api_key_source_auth_header(world, "bdd-invalid-api-key".to_string());
    send_request_and_record(world, vec![header]).await;
}

#[when("the caller sends a request to the surface with a valid API key")]
async fn request_with_valid_api_key(world: &mut SurfaceWorld) {
    let header = build_valid_api_key_source_auth_header(world);
    send_request_and_record(world, vec![header]).await;
}

#[when(expr = "the caller sends a request to the surface path {string} with a valid alternate variant API key")]
async fn request_to_path_with_alternate_variant_api_key(
    world: &mut SurfaceWorld,
    path: String,
) {
    let (header_name, valid_key) = match world
        .surface_config
        .alternate_variant_source_auth
        .as_ref()
    {
        Some(SurfaceSourceAuthConfig::ApiKey(cfg)) => (cfg.header_name.clone(), cfg.valid_key.clone()),
        _ => panic!("alternate variant must have an API Key source auth configured"),
    };
    send_request_to_path_and_record(world, &path, vec![(header_name, valid_key)]).await;
}

#[when("the caller fetches the agent card")]
async fn fetch_agent_card(world: &mut SurfaceWorld) {
    fetch_agent_card_with_headers(world, vec![]).await;
}

#[when("the caller fetches the agent card with extra headers")]
async fn fetch_agent_card_with_extra_headers(
    world: &mut SurfaceWorld,
    step: &cucumber::gherkin::Step,
) {
    let headers = step
        .table
        .as_ref()
        .expect("step must have a table of headers")
        .rows
        .iter()
        .map(|row| {
            (
                row.first()
                    .expect("header row must have a name column")
                    .clone(),
                row.get(1)
                    .expect("header row must have a value column")
                    .clone(),
            )
        })
        .collect();
    fetch_agent_card_with_headers(world, headers).await;
}

async fn fetch_agent_card_with_headers(
    world: &mut SurfaceWorld,
    headers: Vec<(String, String)>,
) {
    ensure_gateway_running(world).await;

    let infra = world.infra.as_ref().unwrap();
    let url =
        format!("http://127.0.0.1:{}{}/.well-known/agent-card.json", infra.gateway_port, world.surface_config.route);

    let mut req = reqwest::Client::new().get(&url);
    for (name, value) in &headers {
        req = req.header(name.as_str(), value.as_str());
    }
    let resp = req
        .send()
        .await
        .expect("agent card request failed");

    let status = resp.status().as_u16();
    let headers = collect_headers(resp.headers());
    let body = resp
        .json()
        .await
        .unwrap_or(serde_json::Value::Null);
    world.caller_response = Some(RecordedResponse { status, headers, body });

    record_mock_observation(world).await;
    record_replacement_mock_observation(world).await;
}

/// Fetch the agent card with a caller-supplied request header.
///
/// Needed for A2A 1.0 negotiation, where the served media type depends on whether
/// the caller signals 1.0 (`A2A-Version: 1.0` or an `Accept` asking for
/// `application/a2a+json`).
#[when(expr = "the caller fetches the agent card with header {string} set to {string}")]
async fn fetch_agent_card_with_header(
    world: &mut SurfaceWorld,
    header_name: String,
    header_value: String,
) {
    ensure_gateway_running(world).await;

    let infra = world.infra.as_ref().unwrap();
    let url =
        format!("http://127.0.0.1:{}{}/.well-known/agent-card.json", infra.gateway_port, world.surface_config.route);

    let resp = reqwest::Client::new()
        .get(&url)
        .header(header_name, header_value)
        .send()
        .await
        .expect("agent card request failed");

    let status = resp.status().as_u16();
    let headers = collect_headers(resp.headers());
    let body = resp
        .json()
        .await
        .unwrap_or(serde_json::Value::Null);
    world.caller_response = Some(RecordedResponse { status, headers, body });

    record_mock_observation(world).await;
    record_replacement_mock_observation(world).await;
}

/// Send an arbitrary A2A method with a caller-supplied request header, so the
/// `A2A-Version` negotiation path can be driven from a scenario.
#[when(expr = "the caller sends A2A method {string} to surface {string} with header {string} set to {string}")]
async fn caller_sends_a2a_method_with_header(
    world: &mut SurfaceWorld,
    method: String,
    surface_name: String,
    header_name: String,
    header_value: String,
) {
    assert!(
        world
            .actors
            .surface(&surface_name)
            .is_some(),
        "unknown surface '{surface_name}'"
    );
    let mut body = build_a2a_message_send_body_with_parts(vec![serde_json::json!({ "kind": "text", "text": "hello" })]);
    body["method"] = serde_json::json!(method);
    set_params_for_method(&mut body, &method);
    send_a2a_proxy_request_and_record(world, body, vec![(header_name, header_value)]).await;
}

#[when("the caller sends two requests that differ only in non-identity fields")]
async fn two_requests_with_different_non_identity_fields(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;

    let infra = world.infra.as_ref().unwrap();

    // First response: region = eu-west-1
    let response_a = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "kind": "message",
            "messageId": "msg-001",
            "role": "agent",
            "parts": [{"kind": "text", "text": "response"}],
            "extensions": [AGENT_IDENTITY_URI],
            "metadata": {
                AGENT_IDENTITY_URI: {
                    "softwareInfo": { "name": "managed-agent", "version": "2.0" },
                    "cloudProvider": "local",
                    "region": "eu-west-1"
                }
            }
        }
    });
    infra
        .mock
        .set_response(response_a)
        .await;

    let url = format!("http://127.0.0.1:{}{}/foo", infra.gateway_port, world.surface_config.route);
    let body = build_a2a_message_send_body("hello");
    world.sent_body = Some(body.clone());
    let client = reqwest::Client::new();

    // Send first request
    let response1 = post_json(&client, &url, &body, &[])
        .await
        .expect("first request failed");
    assert_eq!(response1.status, 200, "first request should succeed");
    let body1 = response1.body;
    let did1 = body1["result"]["metadata"][AGENT_IDENTITY_CREDENTIAL_URI]["did"]
        .as_str()
        .expect("did1 should be present")
        .to_string();
    world
        .collected_dids
        .push(did1);

    // Second response: region = us-east-1 (different non-identity field)
    let response_b = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "kind": "message",
            "messageId": "msg-002",
            "role": "agent",
            "parts": [{"kind": "text", "text": "response"}],
            "extensions": [AGENT_IDENTITY_URI],
            "metadata": {
                AGENT_IDENTITY_URI: {
                    "softwareInfo": { "name": "managed-agent", "version": "2.0" },
                    "cloudProvider": "local",
                    "region": "us-east-1"
                }
            }
        }
    });
    infra
        .mock
        .set_response(response_b)
        .await;

    // Send second request
    let response2 = post_json(&client, &url, &body, &[])
        .await
        .expect("second request failed");
    assert_eq!(response2.status, 200, "second request should succeed");
    let body2 = response2.body.clone();
    let did2 = body2["result"]["metadata"][AGENT_IDENTITY_CREDENTIAL_URI]["did"]
        .as_str()
        .expect("did2 should be present")
        .to_string();
    world
        .collected_dids
        .push(did2);

    record_caller_response(world, response2);
    record_mock_observation(world).await;
    record_replacement_mock_observation(world).await;
}

#[when("the caller sends a request to the surface with a mismatched identity extension")]
async fn request_sent_with_mismatched_identity_extension(world: &mut SurfaceWorld) {
    // The caller declares agent-identity/v1 and carries a payload that does NOT
    // satisfy the protected (MA→AP) Server Identity schema — the `cloudProvider`
    // x-identity field is misspelt as `cloudPrvider`. A surface with only a
    // protected identity slot (and no inbound identity element) must NOT validate
    // the caller against the protected schema, so the request must be forwarded.
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "messageId": "bdd-message",
                "parts": [{ "kind": "text", "text": "hello" }],
                "extensions": [AGENT_IDENTITY_URI],
                "metadata": {
                    AGENT_IDENTITY_URI: {
                        "softwareInfo": { "name": "caller-agent", "version": "1.0" },
                        "cloudPrvider": "local"
                    }
                }
            }
        }
    });
    send_json_request_and_record(world, body, vec![]).await;
}

async fn ask_mcp_surface_for_available_tools_with_headers(
    world: &mut SurfaceWorld,
    headers: Vec<(String, String)>,
) {
    let body = build_mcp_list_tools_body_with_id(serde_json::json!("mcp-tools-list-alpha"));
    send_json_request_and_record(world, body, headers).await;
}

#[when("the caller asks the MCP surface for available tools")]
async fn caller_asks_mcp_surface_for_available_tools(world: &mut SurfaceWorld) {
    ask_mcp_surface_for_available_tools_with_headers(world, vec![]).await;
}

#[when(expr = "the caller asks the MCP surface for available tools using protocol version {string}")]
async fn caller_asks_mcp_surface_using_protocol_version(
    world: &mut SurfaceWorld,
    protocol_version: String,
) {
    let body = build_modern_mcp_list_tools_body(serde_json::json!("modern-mcp-tools-list"), &protocol_version, true);
    send_json_request_and_record(world, body, modern_mcp_request_headers(&protocol_version, "tools/list")).await;
}

#[when(
    expr = "the caller asks the MCP surface for available tools using protocol version {string} without per-request capabilities"
)]
async fn caller_asks_mcp_surface_without_modern_capabilities(
    world: &mut SurfaceWorld,
    protocol_version: String,
) {
    let body = build_modern_mcp_list_tools_body(serde_json::json!("modern-mcp-tools-list"), &protocol_version, false);
    send_json_request_and_record(world, body, modern_mcp_request_headers(&protocol_version, "tools/list")).await;
}

#[when(expr = "the caller sends a modern MCP tool catalog request with mirrored method {string}")]
async fn caller_sends_modern_mcp_list_with_mirrored_method(
    world: &mut SurfaceWorld,
    mirrored_method: String,
) {
    let body =
        build_modern_mcp_list_tools_body(serde_json::json!("modern-mcp-tools-list"), MODERN_MCP_PROTOCOL_VERSION, true);
    send_json_request_and_record(
        world,
        body,
        modern_mcp_request_headers(MODERN_MCP_PROTOCOL_VERSION, &mirrored_method),
    )
    .await;
}

async fn send_mcp_request_through_transit_point(
    world: &mut SurfaceWorld,
    agent_name: &str,
    transit_point: &str,
    body: serde_json::Value,
) {
    let path = format!("/transit/{transit_point}");
    send_mcp_request_through_transit_point_path(world, agent_name, &path, body).await;
}

async fn send_mcp_request_through_transit_point_path(
    world: &mut SurfaceWorld,
    agent_name: &str,
    path: &str,
    body: serde_json::Value,
) {
    world
        .actors
        .expect_target_kind(agent_name, TargetActorKind::ManagedAgent);
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
    let url = format!("http://127.0.0.1:{}{}", outbound_port, path);

    world.sent_body = Some(body.clone());
    let response = reqwest::Client::new()
        .post(&url)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("send MCP request through Transit Point");

    let status = response.status().as_u16();
    let headers = collect_headers(response.headers());
    let body = response
        .json()
        .await
        .unwrap_or(serde_json::Value::Null);
    world.caller_response = Some(RecordedResponse { status, headers, body });

    record_mock_observation(world).await;
    record_replacement_mock_observation(world).await;
}

async fn send_a2a_request_through_transit_point(
    world: &mut SurfaceWorld,
    agent_name: &str,
    transit_point: &str,
    headers: Vec<(String, String)>,
) {
    world
        .actors
        .expect_target_kind(agent_name, TargetActorKind::ManagedAgent);
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
    let url = format!("http://127.0.0.1:{}/transit/{}", outbound_port, transit_point);

    let body = build_a2a_message_send_body("hello");
    world.sent_body = Some(body.clone());
    let client = reqwest::Client::new();
    let mut request = client
        .post(&url)
        .header("content-type", "application/json");
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let response = request
        .json(&body)
        .send()
        .await
        .expect("send A2A request through Transit Point");

    let status = response.status().as_u16();
    let headers = collect_headers(response.headers());
    let body = response
        .json()
        .await
        .unwrap_or(serde_json::Value::Null);
    world.caller_response = Some(RecordedResponse { status, headers, body });

    record_mock_observation(world).await;
    record_replacement_mock_observation(world).await;
}

#[when(
    regex = r#"^managed agent \"([^\"]+)\" sends an A2A message/send request through Transit Point \"([^\"]+)\" with header \"([^\"]+)\" set to \"([^\"]+)\" and header \"([^\"]+)\" set to \"([^\"]+)\"$"#
)]
async fn managed_agent_sends_a2a_request_through_transit_point_with_two_headers(
    world: &mut SurfaceWorld,
    agent_name: String,
    transit_point: String,
    first_header: String,
    first_value: String,
    second_header: String,
    second_value: String,
) {
    send_a2a_request_through_transit_point(
        world,
        &agent_name,
        &transit_point,
        vec![(first_header, first_value), (second_header, second_value)],
    )
    .await;
}

#[when(
    regex = r#"^managed agent \"([^\"]+)\" sends an A2A message/send request through Transit Point \"([^\"]+)\" with header \"([^\"]+)\" set to \"([^\"]+)\"$"#
)]
async fn managed_agent_sends_a2a_request_through_transit_point_with_header(
    world: &mut SurfaceWorld,
    agent_name: String,
    transit_point: String,
    header: String,
    value: String,
) {
    send_a2a_request_through_transit_point(world, &agent_name, &transit_point, vec![(header, value)]).await;
}

#[when(regex = r#"^managed agent \"([^\"]+)\" sends an A2A message/send request through Transit Point \"([^\"]+)\"$"#)]
async fn managed_agent_sends_a2a_request_through_transit_point(
    world: &mut SurfaceWorld,
    agent_name: String,
    transit_point: String,
) {
    send_a2a_request_through_transit_point(world, &agent_name, &transit_point, Vec::new()).await;
}

fn default_value_for_mapped_header(header: &str) -> String {
    match header
        .to_ascii_lowercase()
        .as_str()
    {
        "x-ms-entra-agent-id" => "agent-123".to_string(),
        "x-ms-client-tenant-id" => "tenant-456".to_string(),
        "x-ms-client-session-id" => "session-123".to_string(),
        "x-ms-correlation-id" => "correlation-123".to_string(),
        "x-ms-coreframework-caller-activity-id" => "activity-123".to_string(),
        "x-ms-apim-referrer" => "https://copilot.example/referrer".to_string(),
        other => format!("value-for-{other}"),
    }
}

#[when(
    regex = r#"^managed agent \"([^\"]+)\" sends an A2A message/send request through Transit Point \"([^\"]+)\" without header \"([^\"]+)\"$"#
)]
async fn managed_agent_sends_a2a_request_through_transit_point_without_header(
    world: &mut SurfaceWorld,
    agent_name: String,
    transit_point: String,
    omitted_header: String,
) {
    let configured_headers = world
        .surface_config
        .transit_point
        .as_ref()
        .filter(|configured| configured.alias == transit_point)
        .map(|configured| {
            configured
                .header_metadata_mapping
                .headers
                .iter()
                .map(|row| row.header.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut headers = configured_headers
        .into_iter()
        .filter(|header| !header.eq_ignore_ascii_case(&omitted_header))
        .map(|header| {
            let value = default_value_for_mapped_header(&header);
            (header, value)
        })
        .collect::<Vec<_>>();
    headers.push((format!("{omitted_header}-other"), "not-mapped".to_string()));
    send_a2a_request_through_transit_point(world, &agent_name, &transit_point, headers).await;
}

#[when(expr = "managed agent {string} asks for available tools through Transit Point {string}")]
async fn managed_agent_asks_for_available_tools_through_transit_point(
    world: &mut SurfaceWorld,
    agent_name: String,
    transit_point: String,
) {
    let body = build_mcp_list_tools_body_with_id(serde_json::json!("mcp-tools-list-alpha"));
    send_mcp_request_through_transit_point(world, &agent_name, &transit_point, body).await;
}

#[when(expr = "managed agent {string} asks for available tools through Transit Point path {string}")]
async fn managed_agent_asks_for_available_tools_through_transit_point_path(
    world: &mut SurfaceWorld,
    agent_name: String,
    path: String,
) {
    let body = build_mcp_list_tools_body_with_id(serde_json::json!("mcp-tools-list-alpha"));
    send_mcp_request_through_transit_point_path(world, &agent_name, &path, body).await;
}

#[when(
    expr = "managed agent {string} invokes MCP tool {string} through Transit Point {string} with a result limit of {int}"
)]
async fn managed_agent_invokes_mcp_tool_through_transit_point(
    world: &mut SurfaceWorld,
    agent_name: String,
    tool_name: String,
    transit_point: String,
    limit: i64,
) {
    let body = build_mcp_tool_call_body(&tool_name, serde_json::json!({ "limit": limit }));
    send_mcp_request_through_transit_point(world, &agent_name, &transit_point, body).await;
}

#[when("the caller asks the MCP surface for available tools without a token")]
async fn caller_asks_mcp_surface_for_available_tools_without_token(world: &mut SurfaceWorld) {
    ask_mcp_surface_for_available_tools_with_headers(world, vec![]).await;
}

#[when("the caller asks the MCP surface for available tools with an expired token")]
async fn caller_asks_mcp_surface_for_available_tools_with_expired_token(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let token = create_expired_jwt_for_issuer(get_jwt_source_auth_issuer(world));
    ask_mcp_surface_for_available_tools_with_headers(
        world,
        vec![("authorization".to_string(), format!("Bearer {}", token))],
    )
    .await;
}

#[when("the caller asks the MCP surface for available tools with a malformed token")]
async fn caller_asks_mcp_surface_for_available_tools_with_malformed_token(world: &mut SurfaceWorld) {
    ask_mcp_surface_for_available_tools_with_headers(
        world,
        vec![("authorization".to_string(), "Bearer not-a-jwt".to_string())],
    )
    .await;
}

#[when("the caller asks the MCP surface for available tools with a tampered token")]
async fn caller_asks_mcp_surface_for_available_tools_with_tampered_token(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let token = create_tampered_jwt_for_issuer(get_jwt_source_auth_issuer(world));
    ask_mcp_surface_for_available_tools_with_headers(
        world,
        vec![("authorization".to_string(), format!("Bearer {}", token))],
    )
    .await;
}

#[when("the caller asks the MCP surface for available tools with a valid token")]
async fn caller_asks_mcp_surface_for_available_tools_with_valid_token(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let token = create_valid_jwt_for_issuer(get_jwt_source_auth_issuer(world));
    ask_mcp_surface_for_available_tools_with_headers(
        world,
        vec![("authorization".to_string(), format!("Bearer {}", token))],
    )
    .await;
}

#[when("the caller asks the MCP surface for available tools without an API key")]
async fn caller_asks_mcp_surface_for_available_tools_without_api_key(world: &mut SurfaceWorld) {
    ask_mcp_surface_for_available_tools_with_headers(world, vec![]).await;
}

#[when("the caller asks the MCP surface for available tools with an invalid API key")]
async fn caller_asks_mcp_surface_for_available_tools_with_invalid_api_key(world: &mut SurfaceWorld) {
    let header = build_api_key_source_auth_header(world, "bdd-invalid-api-key".to_string());
    ask_mcp_surface_for_available_tools_with_headers(world, vec![header]).await;
}

#[when("the caller asks the MCP surface for available tools with a valid API key")]
async fn caller_asks_mcp_surface_for_available_tools_with_valid_api_key(world: &mut SurfaceWorld) {
    let header = build_valid_api_key_source_auth_header(world);
    ask_mcp_surface_for_available_tools_with_headers(world, vec![header]).await;
}

#[when(expr = "the caller asks the MCP surface at path {string} for available tools")]
async fn caller_asks_mcp_surface_at_path_for_available_tools(
    world: &mut SurfaceWorld,
    path: String,
) {
    let body = build_mcp_list_tools_body_with_id(serde_json::json!("mcp-tools-list-alpha"));
    send_json_request_to_path_and_record(world, &path, body, vec![]).await;
}

#[when(
    expr = "the caller asks the MCP surface at path {string} for available tools with a valid alternate variant API key"
)]
async fn caller_asks_mcp_surface_at_path_for_available_tools_with_alternate_api_key(
    world: &mut SurfaceWorld,
    path: String,
) {
    let (header_name, valid_key) = match world
        .surface_config
        .alternate_variant_source_auth
        .as_ref()
    {
        Some(SurfaceSourceAuthConfig::ApiKey(cfg)) => (cfg.header_name.clone(), cfg.valid_key.clone()),
        _ => panic!("alternate variant must have an API Key source auth configured"),
    };
    let body = build_mcp_list_tools_body_with_id(serde_json::json!("mcp-tools-list-alpha"));
    send_json_request_to_path_and_record(world, &path, body, vec![(header_name, valid_key)]).await;
}

#[when(expr = "the caller invokes MCP tool {string}")]
async fn mcp_tool_call_sent(
    world: &mut SurfaceWorld,
    tool_name: String,
) {
    let body = build_mcp_tool_call_body(&tool_name, serde_json::json!({}));
    send_json_request_and_record(world, body, vec![]).await;
}

#[when(expr = "the caller invokes the MCP tool {string} for city {string}")]
async fn mcp_tool_call_with_city_argument(
    world: &mut SurfaceWorld,
    tool_name: String,
    city: String,
) {
    let body = build_mcp_tool_call_body(&tool_name, serde_json::json!({ "city": city }));
    send_json_request_and_record(world, body, vec![]).await;
}

#[when(expr = "the caller invokes the MCP tool {string} for city {string} over Legacy SSE")]
async fn mcp_tool_call_with_city_argument_over_legacy_sse(
    world: &mut SurfaceWorld,
    tool_name: String,
    city: String,
) {
    let body = build_mcp_tool_call_body(&tool_name, serde_json::json!({ "city": city }));
    send_legacy_sse_tool_call_and_record(world, body).await;
}

#[when(expr = "the caller invokes the MCP tool {string} for city {string} over Streamable HTTP")]
async fn mcp_tool_call_with_city_argument_over_streamable_http(
    world: &mut SurfaceWorld,
    tool_name: String,
    city: String,
) {
    let body = build_mcp_tool_call_body(&tool_name, serde_json::json!({ "city": city }));
    send_json_request_and_record(world, body, vec![("accept".to_string(), "text/event-stream".to_string())]).await;
}

#[when("the caller connects to the Legacy SSE endpoint")]
async fn caller_connects_to_legacy_sse_endpoint(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;

    let infra = world.infra.as_ref().unwrap();
    let gateway_base = format!("http://127.0.0.1:{}", infra.gateway_port);
    let route = world
        .surface_config
        .route
        .clone();

    let (_, endpoint_path, content_type) =
        crate::bdd_support::sse_client::open_legacy_sse_connection(&gateway_base, &route)
            .await
            .expect("Legacy SSE connection should succeed");

    world.sse_endpoint_path = Some(endpoint_path);
    world.caller_response = Some(RecordedResponse {
        status: 200,
        headers: {
            let mut h = std::collections::HashMap::new();
            h.insert("content-type".to_string(), content_type);
            h
        },
        body: serde_json::Value::Null,
    });
}

#[when(expr = "the caller sends two MCP tool calls over Legacy SSE on the same session")]
async fn caller_sends_two_mcp_tool_calls_over_legacy_sse(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;

    let infra = world.infra.as_ref().unwrap();
    let gateway_base = format!("http://127.0.0.1:{}", infra.gateway_port);
    let route = world
        .surface_config
        .route
        .clone();

    let body = build_mcp_tool_call_body("get_weather", serde_json::json!({ "city": "Paris" }));
    world.sent_body = Some(body.clone());

    let responses = crate::bdd_support::sse_client::legacy_sse_multi_call(&gateway_base, &route, &body, 2)
        .await
        .expect("Legacy SSE multi-call should produce 2 replies");

    world.sse_responses = responses.clone();
    if let Some(last) = responses.into_iter().last() {
        world.caller_response = Some(RecordedResponse {
            status: 200,
            headers: std::collections::HashMap::new(),
            body: last,
        });
    }

    record_mock_observation(world).await;
    record_replacement_mock_observation(world).await;
}

#[when("the caller sends an MCP initialize request over Streamable HTTP")]
async fn mcp_initialize_sent_over_streamable_http(world: &mut SurfaceWorld) {
    let body = build_mcp_initialize_body(serde_json::json!(4242));
    send_json_request_and_record(world, body, vec![("accept".to_string(), "text/event-stream".to_string())]).await;
}

#[when("the caller sends an MCP initialize request")]
async fn mcp_initialize_sent_to_surface(world: &mut SurfaceWorld) {
    let body = build_mcp_initialize_body(serde_json::json!(4242));
    send_json_request_and_record(world, body, vec![]).await;
}

#[when("the caller sends an MCP tools/list request")]
async fn mcp_tools_list_sent_to_surface(world: &mut SurfaceWorld) {
    let body = build_mcp_list_tools_body_with_id(serde_json::json!("mcp-tools-list-alpha"));
    send_json_request_and_record(world, body, vec![]).await;
}

#[when(expr = "the caller sends an MCP initialize request with content type {string}")]
async fn mcp_initialize_sent_with_content_type(
    world: &mut SurfaceWorld,
    content_type: String,
) {
    let body = build_mcp_initialize_body(serde_json::json!(4242));
    send_raw_request_and_record(world, body, &content_type).await;
}

#[when(expr = "the caller invokes the MCP tool {string} with a result limit of {int}")]
async fn mcp_tools_call_sent_to_surface_with_args(
    world: &mut SurfaceWorld,
    tool_name: String,
    limit: i64,
) {
    let body = build_mcp_tool_call_body(&tool_name, serde_json::json!({ "limit": limit }));
    send_json_request_and_record(world, body, vec![]).await;
}

#[when(expr = "OAuth provider {string} redirects the caller back with a valid authorization code")]
pub(crate) async fn oauth_provider_redirects_back_with_valid_code(
    world: &mut SurfaceWorld,
    provider: String,
) {
    let state = latest_consent_state(world, &provider);
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("code", "bdd-valid-code")
        .append_pair("state", &state)
        .finish();
    send_oauth_callback_and_record(world, &provider, &query).await;
    world.oauth_callback_query = Some(query);
}

#[when(expr = "OAuth provider {string} redirects the caller back again with the same state")]
async fn oauth_provider_redirects_back_again_with_the_same_state(
    world: &mut SurfaceWorld,
    provider: String,
) {
    let query = world
        .oauth_callback_query
        .clone()
        .expect("an earlier OAuth callback with a gateway-issued state");
    send_oauth_callback_and_record(world, &provider, &query).await;
}

#[when(expr = "OAuth provider {string} redirects the caller back with a forged state parameter")]
async fn oauth_provider_redirects_with_forged_state(
    world: &mut SurfaceWorld,
    provider: String,
) {
    use base64::Engine;
    let forged = serde_json::json!({
        "agent_did": "did:web:victim-agent.example",
        "user_identity_hash": "victim-user",
        "surface_id": "bdd-surface",
        "credential_provider_id": provider,
        "provider_id": provider,
        "nonce": "forged",
        "expires_at": "2099-01-01T00:00:00Z",
        "code_verifier": null
    });
    let state = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(forged.to_string());
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("code", "bdd-attacker-code")
        .append_pair("state", &state)
        .finish();
    send_oauth_callback_and_record(world, &provider, &query).await;
}

#[when(expr = "OAuth provider {string} redirects the caller back with an invalid state parameter")]
async fn oauth_provider_redirects_with_invalid_state(
    world: &mut SurfaceWorld,
    provider: String,
) {
    ensure_gateway_running(world).await;
    send_oauth_callback_and_record(world, &provider, "code=bdd-valid-code&state=bdd-invalid-state").await;
}

#[when(expr = "OAuth provider {string} redirects the caller back with an expired state parameter")]
async fn oauth_provider_redirects_with_expired_state(
    world: &mut SurfaceWorld,
    provider: String,
) {
    ensure_gateway_running(world).await;
    send_oauth_callback_and_record(world, &provider, "code=bdd-valid-code&state=bdd-expired-state").await;
}

#[when(expr = "OAuth provider {string} redirects the caller back with a provider error")]
async fn oauth_provider_redirects_with_provider_error(
    world: &mut SurfaceWorld,
    provider: String,
) {
    ensure_gateway_running(world).await;
    send_oauth_callback_and_record(world, &provider, "error=access_denied&error_description=bdd-denied").await;
}

async fn send_oauth_callback_and_record(
    world: &mut SurfaceWorld,
    provider: &str,
    query: &str,
) {
    ensure_gateway_running(world).await;
    let infra = world.infra.as_ref().unwrap();
    let url = format!("http://127.0.0.1:{}/v1/identity/oauth/callback/{provider}?{query}", infra.gateway_port);
    let resp = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("send OAuth callback");
    let status = resp.status().as_u16();
    let headers = collect_headers(resp.headers());
    let text = resp
        .text()
        .await
        .expect("read OAuth callback response");
    let body = serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({ "text": text }));
    world.caller_response = Some(RecordedResponse { status, headers, body });
    record_replacement_mock_observation(world).await;
}

fn latest_consent_state(
    world: &SurfaceWorld,
    provider: &str,
) -> String {
    let body = get_response_body_for_when(world);
    let authorization_url = body
        .get("consent_required")
        .and_then(|entries| entries.as_array())
        .and_then(|entries| {
            entries.iter().find(|entry| {
                entry
                    .get("provider_name")
                    .and_then(|name| name.as_str())
                    == Some(provider)
            })
        })
        .and_then(|entry| entry.get("authorization_url"))
        .and_then(|url| url.as_str())
        .unwrap_or_else(|| panic!("expected consent_required authorization_url for provider '{provider}', got {body}"));
    let url = url::Url::parse(authorization_url).expect("authorization_url should be a URL");
    url.query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap_or_else(|| panic!("authorization_url should contain state query parameter: {authorization_url}"))
}

fn get_response_body_for_when(world: &SurfaceWorld) -> &serde_json::Value {
    &world
        .caller_response
        .as_ref()
        .expect("caller response must be recorded")
        .body
}

#[when(expr = "the caller sends a request to the unknown path {string}")]
async fn request_sent_to_unknown_path(
    world: &mut SurfaceWorld,
    path: String,
) {
    ensure_gateway_running(world).await;

    let infra = world.infra.as_ref().unwrap();
    let url = format!("http://127.0.0.1:{}{}", infra.gateway_port, path);

    let resp = reqwest::Client::new()
        .post(&url)
        .header("content-type", "application/json")
        .json(&build_request_body(&world.surface_config.protocol))
        .send()
        .await
        .expect("send request to unknown path");

    let status = resp.status().as_u16();
    let headers = collect_headers(resp.headers());
    let body: serde_json::Value = resp
        .json()
        .await
        .unwrap_or(serde_json::Value::Null);
    world.caller_response = Some(RecordedResponse { status, headers, body });

    record_mock_observation(world).await;
    record_replacement_mock_observation(world).await;
}

#[when(expr = "the caller sends a request to the surface with body")]
async fn request_sent_to_surface_with_docstring_body(
    world: &mut SurfaceWorld,
    step: &cucumber::gherkin::Step,
) {
    let raw = step
        .docstring
        .as_deref()
        .expect("step must have a docstring body")
        .trim();
    let body: serde_json::Value = serde_json::from_str(raw).expect("docstring body must be valid JSON");
    send_json_request_and_record(world, body, vec![]).await;
}

/// Send a docstring JSON body to the surface with one caller-supplied header, so a
/// scenario can vary the A2A method and the `A2A-Version` header together.
#[when(expr = "the caller sends a request to the surface with header {string} set to {string} and body")]
async fn request_sent_to_surface_with_header_and_docstring_body(
    world: &mut SurfaceWorld,
    header_name: String,
    header_value: String,
    step: &cucumber::gherkin::Step,
) {
    let raw = step
        .docstring
        .as_deref()
        .expect("step must have a docstring body")
        .trim();
    let body: serde_json::Value = serde_json::from_str(raw).expect("docstring body must be valid JSON");
    send_json_request_and_record(world, body, vec![(header_name, header_value)]).await;
}

#[when(expr = "the caller sends a request to the surface with extra headers")]
async fn request_sent_to_surface_with_extra_headers(
    world: &mut SurfaceWorld,
    step: &cucumber::gherkin::Step,
) {
    let headers: Vec<(String, String)> = step
        .table
        .as_ref()
        .expect("step must have a table of headers")
        .rows
        .iter()
        .map(|row: &Vec<String>| {
            let name = row
                .first()
                .expect("header row must have a name column")
                .clone();
            let value = row
                .get(1)
                .expect("header row must have a value column")
                .clone();
            (name, value)
        })
        .collect();
    send_request_and_record(world, headers).await;
}

#[when(expr = "{int} callers send requests to the surface sequentially")]
async fn sequential_requests_sent_to_surface(
    world: &mut SurfaceWorld,
    count: usize,
) {
    for _ in 0..count {
        send_request_and_record(world, Default::default()).await;
    }
}

#[when(expr = "{int} callers send requests to the surface concurrently")]
async fn concurrent_requests_sent_to_surface(
    world: &mut SurfaceWorld,
    count: usize,
) {
    ensure_gateway_running(world).await;

    let infra = world.infra.as_ref().unwrap();
    let url = format!("http://127.0.0.1:{}{}/foo", infra.gateway_port, world.surface_config.route);
    let body = build_request_body(&world.surface_config.protocol);

    let handles: Vec<_> = (0..count)
        .map(|_| {
            let url = url.clone();
            let body = body.clone();
            tokio::spawn(async move {
                reqwest::Client::new()
                    .post(&url)
                    .header("content-type", "application/json")
                    .json(&body)
                    .send()
                    .await
                    .expect("concurrent request failed")
                    .status()
                    .as_u16()
            })
        })
        .collect();

    for handle in handles {
        handle
            .await
            .expect("task panicked");
    }

    // Record the last observation so world state is populated for then steps.
    let observations = {
        let infra = world.infra.as_ref().unwrap();
        read_mock_observation(&infra.mock).await
    };
    world.record_primary_observations(observations);
    // Store a placeholder caller_response so the world is not empty.
    world.caller_response = Some(RecordedResponse {
        status: 200,
        headers: Default::default(),
        body: serde_json::Value::Null,
    });
}

fn build_mcp_tool_call_with_valid_identity(tool_name: &str) -> serde_json::Value {
    build_mcp_tool_call_with_meta(
        tool_name,
        serde_json::json!({
            "agentIdentity": build_mcp_agent_identity_payload()
        }),
    )
}

#[when(expr = "the caller invokes MCP tool {string} with a valid inbound identity payload in {string} metadata")]
async fn caller_sends_identity_in_metadata_location(
    world: &mut SurfaceWorld,
    tool_name: String,
    location: String,
) {
    let mut body = build_mcp_tool_call_with_valid_identity(&tool_name);
    match location.as_str() {
        "top-level" => {
            let metadata = body["params"]
                .as_object_mut()
                .unwrap()
                .remove("_meta")
                .unwrap();
            body["_meta"] = metadata;
        }
        "params._meta" => {}
        _ => panic!("unsupported metadata location '{location}'"),
    }
    send_json_request_and_record(world, body, vec![]).await;
}

fn build_mcp_tool_call_with_identity_field(
    tool_name: &str,
    field: &str,
    value: &str,
) -> serde_json::Value {
    let mut identity = build_mcp_agent_identity_payload();
    match field {
        "softwareInfo.name" => identity["softwareInfo"]["name"] = serde_json::Value::String(value.to_string()),
        other => panic!("unsupported MCP inbound identity field '{other}'"),
    }
    build_mcp_tool_call_with_meta(
        tool_name,
        serde_json::json!({
            "agentIdentity": identity
        }),
    )
}

fn build_mcp_tool_call_with_identity_field_condition(
    tool_name: &str,
    field: &str,
    condition: &str,
) -> serde_json::Value {
    let mut identity = build_mcp_agent_identity_payload();
    match (field, condition) {
        ("softwareInfo.name", "missing") => {
            identity["softwareInfo"]
                .as_object_mut()
                .expect("softwareInfo must be an object")
                .remove("name");
        }
        ("softwareInfo.name", "the wrong type") => {
            identity["softwareInfo"]["name"] = serde_json::json!(42);
        }
        ("softwareInfo.name", "outside the configured constraint") => {
            identity["softwareInfo"]["name"] = serde_json::json!("outside-constraint");
        }
        other => panic!("unsupported MCP inbound identity field condition {other:?}"),
    }
    build_mcp_tool_call_with_meta(
        tool_name,
        serde_json::json!({
            "agentIdentity": identity
        }),
    )
}

fn build_mcp_tool_call_with_identity_region(
    tool_name: &str,
    region: &str,
) -> serde_json::Value {
    let mut identity = build_mcp_agent_identity_payload();
    identity["region"] = serde_json::Value::String(region.to_string());
    build_mcp_tool_call_with_meta(
        tool_name,
        serde_json::json!({
            "agentIdentity": identity
        }),
    )
}

pub(crate) async fn invoke_mcp_tool_with_identity_region(
    world: &mut SurfaceWorld,
    tool_name: &str,
    region: &str,
) {
    let body = build_mcp_tool_call_with_identity_region(tool_name, region);
    send_json_request_and_record(world, body, vec![]).await;
}

fn build_mcp_tool_call_with_valid_identity_and_unrelated_metadata(
    tool_name: &str,
    field: &str,
) -> serde_json::Value {
    build_mcp_tool_call_with_meta(
        tool_name,
        serde_json::json!({
            "agentIdentity": build_mcp_agent_identity_payload(),
            field: "bdd-unrelated-metadata-alpha"
        }),
    )
}

fn build_mcp_tool_call_with_metadata_without_identity(tool_name: &str) -> serde_json::Value {
    build_mcp_tool_call_with_meta(
        tool_name,
        serde_json::json!({
            "traceId": "bdd-trace-alpha"
        }),
    )
}

#[when(expr = "the caller invokes MCP tool {string} with a valid inbound identity payload")]
async fn mcp_tool_call_with_valid_identity(
    world: &mut SurfaceWorld,
    tool_name: String,
) {
    let body = build_mcp_tool_call_with_valid_identity(&tool_name);
    send_json_request_and_record(world, body, vec![]).await;
}

#[when(expr = "the caller invokes MCP tool {string} with the same inbound identity and different non-identity fields")]
async fn mcp_tool_call_with_same_identity_and_different_non_identity_fields(
    world: &mut SurfaceWorld,
    tool_name: String,
) {
    invoke_mcp_tool_with_identity_region(world, &tool_name, "us-east-1").await;
}

#[when(
    expr = "the caller invokes MCP tool {string} with a valid inbound identity payload and unrelated MCP metadata field {string}"
)]
async fn mcp_tool_call_with_valid_identity_and_unrelated_metadata(
    world: &mut SurfaceWorld,
    tool_name: String,
    field: String,
) {
    let body = build_mcp_tool_call_with_valid_identity_and_unrelated_metadata(&tool_name, &field);
    send_json_request_and_record(world, body, vec![]).await;
}

#[when(expr = "the caller invokes MCP tool {string} with a schema-invalid inbound identity payload")]
async fn mcp_tool_call_with_invalid_identity(
    world: &mut SurfaceWorld,
    tool_name: String,
) {
    let body = build_mcp_schema_invalid_agent_identity_tool_call_body(&tool_name);
    send_json_request_and_record(world, body, vec![]).await;
}

#[when(expr = "the caller invokes MCP tool {string} without an inbound identity payload")]
async fn mcp_tool_call_without_identity(
    world: &mut SurfaceWorld,
    tool_name: String,
) {
    let body = build_mcp_tool_call_without_meta(&tool_name);
    send_json_request_and_record(world, body, vec![]).await;
}

#[when(expr = "caller {string} invokes MCP tool {string} with a valid token")]
pub(crate) async fn caller_invokes_mcp_tool_with_valid_token(
    world: &mut SurfaceWorld,
    caller: String,
    tool_name: String,
) {
    ensure_gateway_running(world).await;
    let token = create_valid_jwt_for_subject_with_world_claims(world, &caller, serde_json::json!({}));
    let body = build_mcp_tool_call_body(&tool_name, serde_json::json!({}));
    send_json_request_and_record(world, body, vec![("authorization".to_string(), format!("Bearer {token}"))]).await;
}

#[when(expr = "caller {string} invokes MCP tool {string} with a valid token and a valid inbound identity payload")]
pub(crate) async fn caller_invokes_mcp_tool_with_valid_token_and_identity(
    world: &mut SurfaceWorld,
    caller: String,
    tool_name: String,
) {
    ensure_gateway_running(world).await;
    let token = create_valid_jwt_for_subject_with_world_claims(world, &caller, serde_json::json!({}));
    let body = build_mcp_tool_call_with_valid_identity(&tool_name);
    send_json_request_and_record(world, body, vec![("authorization".to_string(), format!("Bearer {token}"))]).await;
}

#[when(
    expr = "caller {string} invokes MCP tool {string} with a valid token and inbound identity field {string} set to {string}"
)]
pub(crate) async fn caller_invokes_mcp_tool_with_valid_token_and_identity_field(
    world: &mut SurfaceWorld,
    caller: String,
    tool_name: String,
    field: String,
    value: String,
) {
    ensure_gateway_running(world).await;
    let token = create_valid_jwt_for_subject_with_world_claims(world, &caller, serde_json::json!({}));
    let body = build_mcp_tool_call_with_identity_field(&tool_name, &field, &value);
    send_json_request_and_record(world, body, vec![("authorization".to_string(), format!("Bearer {token}"))]).await;
}

#[when(expr = "the caller sends an MCP tool call with example identity field {string} set to {string}")]
async fn caller_sends_mcp_tool_call_with_example_identity_field(
    world: &mut SurfaceWorld,
    field: String,
    value: String,
) {
    let body = build_mcp_tool_call_with_identity_field("get_news", &field, &value);
    world.derived_identity_schema = Some(mcp_identity_schema_with_field(&field, false));
    send_json_request_and_record(world, body, vec![]).await;
}

#[when(expr = "the caller invokes MCP tool {string} with inbound identity field {string} set to {string}")]
pub(crate) async fn caller_invokes_mcp_tool_with_identity_field(
    world: &mut SurfaceWorld,
    tool_name: String,
    field: String,
    value: String,
) {
    let body = build_mcp_tool_call_with_identity_field(&tool_name, &field, &value);
    send_json_request_and_record(world, body, vec![]).await;
}

#[when(expr = "the caller invokes MCP tool {string} with inbound identity field {string} missing")]
async fn caller_invokes_mcp_tool_with_identity_field_missing(
    world: &mut SurfaceWorld,
    tool_name: String,
    field: String,
) {
    let body = build_mcp_tool_call_with_identity_field_condition(&tool_name, &field, "missing");
    send_json_request_and_record(world, body, vec![]).await;
}

#[when(expr = "the caller invokes MCP tool {string} with inbound identity field {string} the wrong type")]
async fn caller_invokes_mcp_tool_with_identity_field_wrong_type(
    world: &mut SurfaceWorld,
    tool_name: String,
    field: String,
) {
    let body = build_mcp_tool_call_with_identity_field_condition(&tool_name, &field, "the wrong type");
    send_json_request_and_record(world, body, vec![]).await;
}

#[when(
    expr = "the caller invokes MCP tool {string} with inbound identity field {string} outside the configured constraint"
)]
async fn caller_invokes_mcp_tool_with_identity_field_outside_constraint(
    world: &mut SurfaceWorld,
    tool_name: String,
    field: String,
) {
    let body =
        build_mcp_tool_call_with_identity_field_condition(&tool_name, &field, "outside the configured constraint");
    send_json_request_and_record(world, body, vec![]).await;
}

#[when(expr = "caller {string} asks the MCP surface for available tools with a valid token missing group {string}")]
async fn caller_asks_mcp_surface_for_available_tools_with_valid_token_missing_group(
    world: &mut SurfaceWorld,
    caller: String,
    _group: String,
) {
    ensure_gateway_running(world).await;
    let token = create_valid_jwt_for_subject(get_jwt_source_auth_issuer(world), &caller, serde_json::json!({}));
    ask_mcp_surface_for_available_tools_with_headers(
        world,
        vec![("authorization".to_string(), format!("Bearer {}", token))],
    )
    .await;
}

#[when(expr = "caller {string} asks the MCP surface for available tools with a valid token containing group {string}")]
async fn caller_asks_mcp_surface_for_available_tools_with_named_valid_token_containing_group(
    world: &mut SurfaceWorld,
    caller: String,
    group: String,
) {
    ensure_gateway_running(world).await;
    let token = create_valid_jwt_for_subject(
        get_jwt_source_auth_issuer(world),
        &caller,
        serde_json::json!({ "groups": [group] }),
    );
    ask_mcp_surface_for_available_tools_with_headers(
        world,
        vec![("authorization".to_string(), format!("Bearer {}", token))],
    )
    .await;
}

#[when(expr = "the caller asks the MCP surface for available tools with a token from an untrusted issuer")]
async fn caller_asks_mcp_surface_for_available_tools_with_untrusted_issuer(world: &mut SurfaceWorld) {
    ensure_gateway_running(world).await;
    let token = create_valid_jwt_for_issuer("https://untrusted-issuer.example.test".to_string());
    ask_mcp_surface_for_available_tools_with_headers(
        world,
        vec![("authorization".to_string(), format!("Bearer {}", token))],
    )
    .await;
}

#[when(expr = "the caller asks the MCP surface for available tools with a token outside JWT audience {string}")]
async fn caller_asks_mcp_surface_for_available_tools_with_outside_audience(
    world: &mut SurfaceWorld,
    audience: String,
) {
    ensure_gateway_running(world).await;
    let token = create_valid_jwt_for_issuer_with_audience(
        get_jwt_source_auth_issuer(world),
        serde_json::json!(format!("{audience}-other")),
    );
    ask_mcp_surface_for_available_tools_with_headers(
        world,
        vec![("authorization".to_string(), format!("Bearer {}", token))],
    )
    .await;
}

#[when(expr = "the caller invokes MCP tool {string} with MCP metadata but no inbound identity field")]
async fn build_mcp_tool_call_with_meta_without_identity(
    world: &mut SurfaceWorld,
    tool_name: String,
) {
    let body = build_mcp_tool_call_with_metadata_without_identity(&tool_name);
    send_json_request_and_record(world, body, vec![]).await;
}

#[when("the caller sends a malformed MCP request")]
async fn mcp_malformed_request_sent(world: &mut SurfaceWorld) {
    send_raw_string_request_and_record(world, "{\"jsonrpc\":", "application/json").await;
}

#[when("the caller sends a batch of modern MCP tool catalog requests")]
async fn mcp_modern_batch_sent(world: &mut SurfaceWorld) {
    let batch = serde_json::Value::Array(vec![
        build_modern_mcp_list_tools_body(
            serde_json::json!("modern-mcp-batch-first"),
            MODERN_MCP_PROTOCOL_VERSION,
            true,
        ),
        build_modern_mcp_list_tools_body(
            serde_json::json!("modern-mcp-batch-second"),
            MODERN_MCP_PROTOCOL_VERSION,
            true,
        ),
    ]);
    send_json_request_and_record(world, batch, modern_mcp_request_headers(MODERN_MCP_PROTOCOL_VERSION, "tools/list"))
        .await;
}

#[when(expr = "the caller asks the MCP surface for available tools with header {string} set to {string}")]
async fn caller_asks_mcp_surface_with_header(
    world: &mut SurfaceWorld,
    header: String,
    value: String,
) {
    ask_mcp_surface_for_available_tools_with_headers(world, vec![(header, value)]).await;
}

#[when("the caller sends an MCP request without a method")]
async fn mcp_request_without_method_sent(world: &mut SurfaceWorld) {
    let body = build_mcp_request_without_method_body(serde_json::json!("mcp-missing-method"));
    send_json_request_and_record(world, body, vec![]).await;
}

#[when("the caller sends an MCP notification")]
async fn mcp_notification_sent(world: &mut SurfaceWorld) {
    let body = build_mcp_initialized_notification_body();
    send_json_request_and_record(world, body, vec![]).await;
}

pub async fn start_mock_agents(world: &mut SurfaceWorld) {
    let fixtures = world
        .actors
        .targets()
        .iter()
        .map(|(key, target)| {
            target
                .fixture
                .as_ref()
                .unwrap_or_else(|| panic!("target '{}' fixture must be present", key))
                .clone()
        })
        .collect::<Vec<_>>();

    let fixtures_to_start = fixtures
        .iter()
        .filter(|fixture| {
            !world
                .runtimes
                .targets
                .contains_key(&fixture.key)
        })
        .collect::<Vec<_>>();

    for fixture in fixtures_to_start {
        debug_line(world, &format!("starting mock target '{}'", fixture.key));

        {
            world
                .runtimes
                .reserved_ports
                .get_mut(&fixture.port)
                .unwrap_or_else(|| {
                    panic!("reserved port '{}' for target '{}' must be present", fixture.port, fixture.key)
                })
                .release_listener();
        }

        let mock_agent_server = MockServer::start_server_with_fixture(fixture.clone()).await;
        world
            .runtimes
            .targets
            .insert(fixture.key.clone(), mock_agent_server);
        world
            .runtimes
            .reserved_ports
            .remove(&fixture.port);
    }
}

async fn start_gateways(world: &mut SurfaceWorld) {
    let fixtures = world
        .actors
        .gateway_instances()
        .iter()
        .map(|(key, target)| {
            target
                .fixture
                .as_ref()
                .unwrap_or_else(|| panic!("target '{}' fixture must be present", key))
                .clone()
        })
        .collect::<Vec<_>>();
    let fixtures_to_start = fixtures
        .iter()
        .filter(|fixture| {
            !world
                .runtimes
                .gateway_instances
                .contains_key(&fixture.key)
        })
        .collect::<Vec<_>>();

    for fixture in fixtures_to_start {
        debug_line(world, &format!("starting gateway '{}'", fixture.key));
        let inbound_port = fixture.gateway_port;
        let outbound_port = fixture.outbound_listener_port;

        {
            world
                .runtimes
                .reserved_ports
                .get_mut(&inbound_port)
                .unwrap_or_else(|| {
                    panic!("reserved port '{}' for target '{}' must be present", inbound_port, fixture.key)
                })
                .release_listener();
        }

        if let Some(outbound_listener_port) = outbound_port {
            world
                .runtimes
                .reserved_ports
                .get_mut(&outbound_listener_port)
                .expect("reserved outbound port must be present")
                .release_listener();
        }

        let gateway = fixture.start_gateway().await;
        world
            .runtimes
            .gateway_instances
            .insert(fixture.key.clone(), gateway);

        world
            .runtimes
            .reserved_ports
            .remove(&inbound_port);
        if let Some(outbound_listener_port) = outbound_port {
            world
                .runtimes
                .reserved_ports
                .remove(&outbound_listener_port);
        }
    }
}

async fn setup_bootstrapped(world: &mut SurfaceWorld) {
    debug_line(world, &format!("world state at start of before setup is bootstrapped: {:#?}", world));
    if world.debug {
        let log_path = world
            .temp_dir
            .as_ref()
            .join("world.log");
        let log_path = log_path
            .to_str()
            .expect("log path must be valid UTF-8");
        log_to_file(log_path, &format!("{:#?}", world));
    }

    start_mock_agents(world).await;
    start_gateways(world).await;

    debug_line(world, &format!("world state after setup is bootstrapped: {:#?}", world));
}

/// Send an A2A request with a specific JSON-RPC method name to a surface path, so a
/// scenario can drive the v0.3 slash-form and the v1.0 PascalCase spelling of the
/// same operation and observe what policy sees.
#[when(expr = "the caller sends A2A method {string} to the surface path {string} in gateway {string}")]
async fn request_with_method_sent_to_surface_path_in_gateway(
    world: &mut SurfaceWorld,
    method: String,
    path: String,
    gateway_key: String,
) {
    ensure_gateway_running(world).await;
    let mut body = build_request_body("a2a");
    body["method"] = serde_json::json!(method);
    let gateway_port = world
        .actors
        .gateway_instance(&gateway_key)
        .expect("Gateway must be present")
        .fixture
        .clone()
        .expect("Fixture must be present")
        .gateway_port;

    let url = format!("http://127.0.0.1:{}{}", gateway_port, path);

    world.sent_body = Some(body.clone());

    let client = reqwest::Client::new();
    let response = post_json(&client, &url, &body, &[])
        .await
        .expect("send request to gateway");

    record_caller_response(world, response);
}

#[when(expr = "the caller sends A2A request to the surface path {string} in gateway {string}")]
async fn request_sent_to_surface_path_in_gateway(
    world: &mut SurfaceWorld,
    path: String,
    gateway_key: String,
) {
    ensure_gateway_running(world).await;
    let body = build_request_body("a2a");
    let gateway_port = world
        .actors
        .gateway_instance(&gateway_key)
        .expect("Gateway must be present")
        .fixture
        .clone()
        .expect("Fixture must be present")
        .gateway_port;

    let url = format!("http://127.0.0.1:{}{}", gateway_port, path);

    world.sent_body = Some(body.clone());

    let client = reqwest::Client::new();
    let response = post_json(&client, &url, &body, &[])
        .await
        .expect("send request to gateway");

    record_caller_response(world, response);
}

/// Sends a modern `tools/call`. A streaming upstream keeps its response open,
/// so the response is kept for later steps to read instead of being drained.
pub(crate) async fn send_modern_mcp_tool_call(
    world: &mut SurfaceWorld,
    tool_name: &str,
    protocol_version: &str,
    extra_headers: Vec<(String, String)>,
) {
    use crate::bdd_support::mock_server::MockStream;

    let body = crate::bdd_support::json_rpc::build_modern_mcp_tool_call_body(
        serde_json::json!("bdd-modern-call"),
        tool_name,
        protocol_version,
    );
    let mut headers = modern_mcp_request_headers(protocol_version, "tools/call");
    headers.push(("Mcp-Name".to_string(), tool_name.to_string()));
    headers.extend(extra_headers);
    let streaming = matches!(
        world
            .collaborator_target(PRIMARY_COLLABORATOR_KEY)
            .configured_response
            .stream,
        MockStream::ProgressThenRelease | MockStream::Quiet
    );
    if !streaming {
        send_json_request_and_record(world, body, headers).await;
        return;
    }
    ensure_gateway_running(world).await;
    let url = format!(
        "http://127.0.0.1:{}{}/foo",
        world
            .infra
            .as_ref()
            .unwrap()
            .gateway_port,
        world.surface_config.route
    );
    world.sent_body = Some(body.clone());
    let mut request = reqwest::Client::new()
        .post(&url)
        .header("content-type", "application/json")
        .json(&body);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .expect("send modern MCP request to gateway");
    world.caller_response = Some(RecordedResponse {
        status: response.status().as_u16(),
        headers: collect_headers(response.headers()),
        body: serde_json::Value::Null,
    });
    world.mcp_stream = Some(response);
    world
        .mcp_stream_buffer
        .clear();
    world.mcp_stream_closed_after_final = false;
}

#[when(expr = "the caller invokes MCP tool {string} using protocol version {string} without a protocol session")]
async fn caller_invokes_modern_mcp_tool(
    world: &mut SurfaceWorld,
    tool_name: String,
    protocol_version: String,
) {
    send_modern_mcp_tool_call(world, &tool_name, &protocol_version, Vec::new()).await;
}

#[when(expr = "the caller invokes MCP tool {string} using protocol version {string} with Origin {string}")]
async fn caller_invokes_modern_mcp_tool_with_origin(
    world: &mut SurfaceWorld,
    tool_name: String,
    protocol_version: String,
    origin: String,
) {
    send_modern_mcp_tool_call(world, &tool_name, &protocol_version, vec![("Origin".to_string(), origin)]).await;
}

#[when("the caller closes the MCP response stream")]
fn caller_closes_mcp_response_stream(world: &mut SurfaceWorld) {
    let stream = world.mcp_stream.take();
    assert!(stream.is_some(), "no open MCP response stream to close");
    drop(stream);
}
