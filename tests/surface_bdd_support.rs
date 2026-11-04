#![allow(dead_code)]

#[path = "bdd_support/mod.rs"]
mod bdd_support;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::thread;

use tempfile::TempDir;

use bdd_support::admin_client::AdminApiClient;
use bdd_support::config;
use bdd_support::config::single_surface_fixture::{
    ApiKeyProviderSourceAuthConfig, McpToolPolicyFixture, SurfaceConfigBuilder, SurfaceSourceAuthConfig,
    SurfaceTransitPointConfig,
};
use bdd_support::gateway_process::{GatewayProcess, SURFACE_TEST_AUTH_TOKEN as TEST_AUTH_TOKEN};

#[test]
fn reserve_free_port_does_not_reuse_ports_within_the_test_process_under_concurrency() {
    let ports = Arc::new(Mutex::new(Vec::new()));
    let reservations = Arc::new(Mutex::new(Vec::new()));
    let workers = (0..128)
        .map(|_| {
            let ports = Arc::clone(&ports);
            let reservations = Arc::clone(&reservations);
            thread::spawn(move || {
                let (port, reservation) = config::reserve_free_port("");
                ports
                    .lock()
                    .unwrap()
                    .push(port);
                reservations
                    .lock()
                    .unwrap()
                    .push(reservation);
            })
        })
        .collect::<Vec<_>>();

    for worker in workers {
        worker.join().unwrap();
    }

    let ports = ports.lock().unwrap();
    let unique = ports
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    assert_eq!(unique.len(), ports.len(), "allocated ports should be unique: {ports:?}");
    assert!(
        ports
            .iter()
            .all(|port| (20_000..=29_999).contains(port)),
        "allocated ports should stay out of the OS ephemeral range: {ports:?}"
    );
}

#[test]
fn write_config_seeds_surface_by_default() {
    let temp_dir = TempDir::new().unwrap();
    let surface_config = SurfaceConfigBuilder::default();

    config::single_surface_writer::write_single_surface_config(
        temp_dir.path(),
        32001,
        "http://127.0.0.1:9",
        &surface_config,
        None,
    );

    assert!(
        temp_dir
            .path()
            .join("_storage/agent_surfaces/bdd-surface.json")
            .exists()
    );
}

#[test]
fn write_config_uses_configured_surface_name() {
    let temp_dir = TempDir::new().unwrap();
    let surface_config = SurfaceConfigBuilder {
        surface_name: Some("alpha".to_string()),
        ..SurfaceConfigBuilder::default()
    };

    config::single_surface_writer::write_single_surface_config(
        temp_dir.path(),
        32003,
        "http://127.0.0.1:9",
        &surface_config,
        None,
    );

    let surface_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            temp_dir
                .path()
                .join("_storage/agent_surfaces/bdd-surface.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(surface_json["name"], "alpha");
}

#[test]
fn write_config_writes_the_access_point_a2a_settings() {
    let temp_dir = TempDir::new().unwrap();
    let a2a = serde_json::json!({ "accepted_versions": ["1.0"], "validation": "full" });
    let surface_config = SurfaceConfigBuilder {
        protocol: "a2a".to_string(),
        a2a_settings: Some(a2a.clone()),
        ..SurfaceConfigBuilder::default()
    };

    config::single_surface_writer::write_single_surface_config(
        temp_dir.path(),
        32020,
        "http://127.0.0.1:9",
        &surface_config,
        None,
    );

    let surface_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            temp_dir
                .path()
                .join("_storage/agent_surfaces/bdd-surface.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(surface_json["access_point"]["a2a"], a2a);
}

#[test]
fn write_config_seeds_api_key_provider_source_auth_fixture() {
    let temp_dir = TempDir::new().unwrap();
    let surface_config = SurfaceConfigBuilder {
        source_auth: Some(SurfaceSourceAuthConfig::ApiKeyProvider(ApiKeyProviderSourceAuthConfig {
            header_name: "X-API-Key".to_string(),
            agent_id: "agent".to_string(),
            key_id: "key".to_string(),
            client_id: "client".to_string(),
            valid_key: "valid".to_string(),
        })),
        ..SurfaceConfigBuilder::default()
    };

    config::single_surface_writer::write_single_surface_config(
        temp_dir.path(),
        32004,
        "http://127.0.0.1:9",
        &surface_config,
        None,
    );

    let surface_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            temp_dir
                .path()
                .join("_storage/agent_surfaces/bdd-surface.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(surface_json["access_point"]["caller_authentication"]["methods"][0]["type"], "api_key_provider");
    assert_eq!(surface_json["access_point"]["caller_authentication"]["methods"][0]["agent_id"], "agent");

    let key_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            temp_dir
                .path()
                .join("_storage/api_keys/agent/key.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(key_json["key_id"], "key");
    assert_eq!(key_json["agent_id"], "agent");
    assert_eq!(key_json["client_id"], "client");
    // The raw secret is never persisted — only its SHA-256 hash.
    assert!(key_json["secret"].is_null());
    let expected_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"valid");
        hex::encode(hasher.finalize())
    };
    assert_eq!(key_json["secret_hash"], expected_hash);
    assert_eq!(key_json["status"], "active");
}

#[test]
fn write_config_can_skip_seed_surface_and_register_api_route() {
    let temp_dir = TempDir::new().unwrap();
    let surface_config = SurfaceConfigBuilder {
        route: "/created".to_string(),
        registered_routes: vec!["/created".to_string(), "/updated".to_string(), "/created".to_string()],
        seed_surface: false,
        ..SurfaceConfigBuilder::default()
    };

    config::single_surface_writer::write_single_surface_config(
        temp_dir.path(),
        32002,
        "http://127.0.0.1:9",
        &surface_config,
        None,
    );

    assert!(
        !temp_dir
            .path()
            .join("_storage/agent_surfaces/bdd-surface.json")
            .exists()
    );

    let gateway_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            temp_dir
                .path()
                .join("gateway.json"),
        )
        .unwrap(),
    )
    .unwrap();

    let legacy_channels = gateway_json["channels"]
        .as_array()
        .unwrap();
    let prefixes: Vec<&str> = legacy_channels
        .iter()
        .filter_map(|legacy_channel| legacy_channel["prefix"].as_str())
        .collect();
    assert_eq!(prefixes, vec!["/created", "/updated"]);
    assert_eq!(gateway_json["routes"]["api"]["type"], "identity_api");
    assert_eq!(gateway_json["routes"]["api"]["prefix"], "/api");
}

#[test]
fn write_config_seeds_mcp_tool_policy_definition() {
    let temp_dir = TempDir::new().unwrap();
    let surface_config = SurfaceConfigBuilder {
        protocol: "mcp".to_string(),
        mcp_tool_policy: Some(McpToolPolicyFixture {
            allowed_tool: "get_news".to_string(),
            policy_definition_id: "bdd-mcp-tool-policy".to_string(),
            rego: "package surface.policy\n\ndefault allow = false\n".to_string(),
        }),
        ..SurfaceConfigBuilder::default()
    };

    config::single_surface_writer::write_single_surface_config(
        temp_dir.path(),
        32004,
        "http://127.0.0.1:9",
        &surface_config,
        None,
    );

    let definition: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            temp_dir
                .path()
                .join("_storage/policies/bdd-mcp-tool-policy.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(definition["id"], "bdd-mcp-tool-policy");
    assert_eq!(definition["policy_type"], "agent_surface");
    assert_eq!(definition["enabled"], true);

    let surface_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            temp_dir
                .path()
                .join("_storage/agent_surfaces/bdd-surface.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(surface_json["target"]["mcp_tool_policies_enabled"], true);
    assert_eq!(surface_json["target"]["mcp_tool_policies"][0]["tool_name"], "get_news");
    assert_eq!(surface_json["target"]["mcp_tool_policies"][0]["policy_definition_id"], "bdd-mcp-tool-policy");
}

#[test]
fn write_config_can_seed_transit_point_with_outbound_listener() {
    let temp_dir = TempDir::new().unwrap();
    let surface_config = SurfaceConfigBuilder {
        transit_points: vec![SurfaceTransitPointConfig::new("alpha", "mcp")],
        ..SurfaceConfigBuilder::default()
    };

    config::single_surface_writer::write_single_surface_config_with_outbound_listener(
        temp_dir.path(),
        32005,
        32015,
        "http://127.0.0.1:9",
        &HashMap::from([("alpha".to_string(), "http://127.0.0.1:10".to_string())]),
        &surface_config,
        None,
    );

    let gateway_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            temp_dir
                .path()
                .join("gateway.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(gateway_json["listeners"][1]["listener_type"], "outbound");
    assert_eq!(gateway_json["listeners"][1]["port"], 32015);

    let surface_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            temp_dir
                .path()
                .join("_storage/agent_surfaces/bdd-surface.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(surface_json["transit"]["outbound_listen_address"], "http://localhost:32015");
    assert_eq!(surface_json["transit"]["points"][0]["alias"], "alpha");
    assert_eq!(surface_json["transit"]["points"][0]["target_endpoint"], "http://127.0.0.1:10");
}

#[test]
fn write_config_gives_each_transit_point_its_own_destination_trust_checks_and_policy() {
    let temp_dir = TempDir::new().unwrap();
    let mut alpha = SurfaceTransitPointConfig::new("alpha", "a2a");
    alpha
        .trust_check_list
        .push(serde_json::json!({ "id": "alpha-check" }));
    alpha.policy = Some(config::config_tree::PolicyDefinitionFixture::new(
        "alpha-policy",
        "Alpha policy",
        "package surface.policy\n\ndefault allow := true\n",
    ));
    let surface_config = SurfaceConfigBuilder {
        transit_points: vec![alpha, SurfaceTransitPointConfig::new("bravo", "a2a")],
        ..SurfaceConfigBuilder::default()
    };

    config::single_surface_writer::write_single_surface_config_with_outbound_listener(
        temp_dir.path(),
        32005,
        32015,
        "http://127.0.0.1:9",
        &HashMap::from([
            ("alpha".to_string(), "http://127.0.0.1:10".to_string()),
            ("bravo".to_string(), "http://127.0.0.1:11".to_string()),
        ]),
        &surface_config,
        None,
    );

    let surface_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            temp_dir
                .path()
                .join("_storage/agent_surfaces/bdd-surface.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let points = &surface_json["transit"]["points"];
    assert_eq!(points[0]["alias"], "alpha");
    assert_eq!(points[0]["target_endpoint"], "http://127.0.0.1:10");
    assert_eq!(points[0]["trust_check_list"][0]["id"], "alpha-check");
    assert_eq!(points[0]["policy"]["policy_definition_id"], "alpha-policy");
    assert_eq!(points[1]["alias"], "bravo");
    assert_eq!(points[1]["target_endpoint"], "http://127.0.0.1:11");
    assert!(
        points[1]
            .get("trust_check_list")
            .is_none()
    );
    assert!(
        points[1]
            .get("policy")
            .is_none()
    );
    assert!(
        surface_json["target"]
            .get("trust_check_list")
            .is_none()
    );
    assert!(
        temp_dir
            .path()
            .join("_storage/policies/alpha-policy.json")
            .exists()
    );
}

async fn spawn_gateway(seed_surface: bool) -> (TempDir, GatewayProcess) {
    let temp_dir = TempDir::new().unwrap();
    let (gateway_port, mut port_reservation) = config::reserve_free_port("");
    let surface_config = SurfaceConfigBuilder {
        seed_surface,
        ..SurfaceConfigBuilder::default()
    };

    config::single_surface_writer::write_single_surface_config(
        temp_dir.path(),
        gateway_port,
        "http://127.0.0.1:9",
        &surface_config,
        None,
    );

    let config_path = temp_dir
        .path()
        .join("config.toml");
    port_reservation.release_listener();
    let mut gateway = GatewayProcess::start_surface(&config_path, temp_dir.path())
        .with_port(gateway_port)
        .with_port_reservation(port_reservation);
    if let Err(e) = gateway
        .try_wait_until_ready(std::time::Duration::from_secs(60))
        .await
    {
        let kept = temp_dir.keep();
        eprintln!("[surface-bdd-support] gateway readiness failed; preserving temp dir at {}", kept.display());
        panic!("{e}");
    }

    (temp_dir, gateway)
}

#[tokio::test]
async fn gateway_process_exposes_test_login_endpoint() {
    let (_temp_dir, gateway) = spawn_gateway(false).await;

    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/internal/test-support/auth/login", gateway.port))
        .header("x-test-token", TEST_AUTH_TOKEN)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let response_body: serde_json::Value = response.json().await.unwrap();
    let session_token = response_body["session_token"]
        .as_str()
        .unwrap();
    assert!(!session_token.is_empty());
    assert_eq!(response_body["username"], "test-user");
}

#[tokio::test]
async fn admin_api_client_bootstraps_test_session_and_sends_authenticated_requests() {
    let (_temp_dir, gateway) = spawn_gateway(false).await;
    let client = AdminApiClient::new(gateway.port, TEST_AUTH_TOKEN, "surface-bdd-support");

    client
        .bootstrap_test_session()
        .await
        .unwrap();
    let response = client
        .list_gateways_recorded()
        .await
        .unwrap();

    assert_eq!(response.status, 200);
    assert!(
        response
            .body
            .as_array()
            .is_some_and(|gateways| !gateways.is_empty()),
        "expected authenticated gateway list response, got {}",
        response.body
    );
}

#[tokio::test]
async fn gateway_process_rejects_invalid_test_login_token() {
    let (_temp_dir, gateway) = spawn_gateway(false).await;

    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/internal/test-support/auth/login", gateway.port))
        .header("x-test-token", "wrong-token")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_fresh_gateway_refuses_registration_without_the_setup_token() {
    let (_temp_dir, gateway) = start_fresh_gateway(&HashMap::new()).await;

    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/auth/register/start", gateway.port))
        .json(&serde_json::json!({ "username": "first-admin" }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(response.text().await.unwrap(), "A valid setup token is required to register the first administrator");
}

const OPERATOR_SETUP_TOKEN: &str = "surface-bdd-operator-setup-token-0123456789-abcdef";

const GATEWAY_START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Starts a gateway on an empty store and waits until it is ready, which it proves by writing
/// the setup token file in its own storage before its port answers.
async fn start_fresh_gateway(extra_env: &HashMap<String, String>) -> (TempDir, GatewayProcess) {
    let (temp_dir, mut gateway) = start_gateway_keeping_its_log(extra_env);
    if let Err(error) = gateway
        .wait_until_ready_after_writing(&setup_token_file(&temp_dir), GATEWAY_START_TIMEOUT)
        .await
    {
        panic!("{error}\n{}", gateway_log(&temp_dir));
    }
    (temp_dir, gateway)
}

fn start_gateway_keeping_its_log(extra_env: &HashMap<String, String>) -> (TempDir, GatewayProcess) {
    let temp_dir = TempDir::new().unwrap();
    let (gateway_port, mut port_reservation) = config::reserve_free_port("");
    let surface_config = SurfaceConfigBuilder {
        seed_surface: false,
        keeps_gateway_log: true,
        ..SurfaceConfigBuilder::default()
    };
    config::single_surface_writer::write_single_surface_config(
        temp_dir.path(),
        gateway_port,
        "http://127.0.0.1:9",
        &surface_config,
        None,
    );
    let config_path = temp_dir
        .path()
        .join("config.toml");
    port_reservation.release_listener();
    let gateway = GatewayProcess::start_surface_logged_with_env(&config_path, temp_dir.path(), extra_env)
        .with_port(gateway_port)
        .with_port_reservation(port_reservation);
    (temp_dir, gateway)
}

fn setup_token_file(temp_dir: &TempDir) -> std::path::PathBuf {
    temp_dir
        .path()
        .join("_storage/passkeys/setup-token")
}

fn gateway_log(temp_dir: &TempDir) -> String {
    std::fs::read_to_string(
        temp_dir
            .path()
            .join("gateway.log"),
    )
    .unwrap()
}

async fn setup_required(gateway: &GatewayProcess) -> bool {
    let mode: serde_json::Value = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/api/v1/auth/mode", gateway.port))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(mode["mode"], "passkey");
    mode["setup_required"]
        .as_bool()
        .unwrap()
}

async fn start_registration(
    gateway: &GatewayProcess,
    setup_token: Option<&str>,
) -> reqwest::Response {
    let mut body = serde_json::json!({ "username": "first-admin" });
    if let Some(setup_token) = setup_token {
        body["setup_token"] = serde_json::json!(setup_token);
    }
    reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/api/auth/register/start", gateway.port))
        .json(&body)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn a_fresh_gateway_starts_registration_with_the_token_from_its_file() {
    let (temp_dir, gateway) = start_fresh_gateway(&HashMap::new()).await;
    let token = std::fs::read_to_string(setup_token_file(&temp_dir))
        .unwrap()
        .trim()
        .to_string();

    let registration = start_registration(&gateway, Some(&token)).await;

    assert_eq!(registration.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = registration
        .json()
        .await
        .unwrap();
    assert!(
        body["challenge_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
    assert!(setup_required(&gateway).await);
    assert_eq!(token.len(), 43);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(setup_token_file(&temp_dir))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let log = gateway_log(&temp_dir);
    assert!(log.contains("No user exists yet: register the first administrator with the setup token in"));
    assert!(log.contains("_storage/passkeys/setup-token"));
    assert!(!log.contains(&token), "the gateway log must not contain the setup token");
}

#[tokio::test]
async fn a_gateway_takes_its_setup_token_from_ag_setup_token() {
    let env = HashMap::from([("AG_SETUP_TOKEN".to_string(), format!("string://{OPERATOR_SETUP_TOKEN}"))]);
    let (temp_dir, gateway) = start_fresh_gateway(&env).await;

    let with_operator_token = start_registration(&gateway, Some(OPERATOR_SETUP_TOKEN)).await;
    let with_other_token = start_registration(&gateway, Some(&OPERATOR_SETUP_TOKEN.replace('a', "A"))).await;

    assert_eq!(with_operator_token.status(), reqwest::StatusCode::OK);
    assert_eq!(with_other_token.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(std::fs::read_to_string(setup_token_file(&temp_dir)).unwrap(), format!("{OPERATOR_SETUP_TOKEN}\n"));
    assert!(!gateway_log(&temp_dir).contains(OPERATOR_SETUP_TOKEN), "the gateway log must not contain the setup token");
}

#[tokio::test]
async fn an_invalid_ag_setup_token_stops_the_gateway() {
    let invalid = "too-short-surface-bdd-setup-token";
    let env = HashMap::from([("AG_SETUP_TOKEN".to_string(), invalid.to_string())]);
    let (temp_dir, mut gateway) = start_gateway_keeping_its_log(&env);

    let status = gateway
        .wait_for_exit(GATEWAY_START_TIMEOUT)
        .await
        .unwrap();

    assert!(!status.success(), "{status}");
    let log = gateway_log(&temp_dir);
    assert!(log.contains("AG_SETUP_TOKEN must be 43 to 256 printable ASCII characters"), "{log}");
    assert!(!log.contains(invalid), "the gateway log must not contain the rejected token");
    assert!(!setup_token_file(&temp_dir).exists());
}

#[tokio::test]
async fn a_gateway_with_a_user_reports_setup_not_required() {
    let (_temp_dir, gateway) = start_fresh_gateway(&HashMap::new()).await;
    let required_before = setup_required(&gateway).await;
    AdminApiClient::new(gateway.port, TEST_AUTH_TOKEN, "surface-bdd-support")
        .bootstrap_test_session()
        .await
        .unwrap();

    let required_after = setup_required(&gateway).await;
    let registration = start_registration(&gateway, None).await;

    assert!(required_before);
    assert!(!required_after);
    assert_eq!(registration.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn the_gateway_limits_registration_starts_from_one_client() {
    let (_temp_dir, gateway) = start_fresh_gateway(&HashMap::new()).await;

    let mut within_the_limit = Vec::new();
    for _ in 0..5 {
        within_the_limit.push(
            start_registration(&gateway, None)
                .await
                .status(),
        );
    }
    let over_the_limit = start_registration(&gateway, None).await;

    assert_eq!(within_the_limit, vec![reqwest::StatusCode::FORBIDDEN; 5], "the first five reach the setup token check");
    assert_eq!(over_the_limit.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = over_the_limit.headers()[reqwest::header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=900).contains(&retry_after), "retry-after {retry_after}");
}
