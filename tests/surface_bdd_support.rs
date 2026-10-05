#![allow(dead_code)]

#[path = "bdd_support/mod.rs"]
mod bdd_support;

use std::collections::HashSet;
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
        transit_point: Some(SurfaceTransitPointConfig {
            alias: "alpha".to_string(),
            protocol: "mcp".to_string(),
            header_metadata_mapping: Default::default(),
            managed_identity: None,
        }),
        ..SurfaceConfigBuilder::default()
    };

    config::single_surface_writer::write_single_surface_config_with_outbound_listener(
        temp_dir.path(),
        32005,
        32015,
        "http://127.0.0.1:9",
        "http://127.0.0.1:10",
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
