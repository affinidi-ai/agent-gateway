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

fn written_log_directory(surface_config: &SurfaceConfigBuilder) -> (TempDir, Option<String>) {
    let temp_dir = TempDir::new().unwrap();
    config::single_surface_writer::write_single_surface_config(
        temp_dir.path(),
        32030,
        "http://127.0.0.1:9",
        surface_config,
        None,
    );
    let config: toml::Table = std::fs::read_to_string(
        temp_dir
            .path()
            .join("config.toml"),
    )
    .unwrap()
    .parse()
    .unwrap();
    let log_directory = config["logging"]
        .get("log_directory")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    (temp_dir, log_directory)
}

#[test]
fn write_config_sets_no_log_directory_by_default() {
    let (_temp_dir, log_directory) = written_log_directory(&SurfaceConfigBuilder::default());

    assert_eq!(log_directory, None);
}

#[test]
fn write_config_points_the_log_directory_into_storage_when_asked() {
    let surface_config = SurfaceConfigBuilder {
        writes_log_directory: true,
        ..SurfaceConfigBuilder::default()
    };

    let (temp_dir, log_directory) = written_log_directory(&surface_config);

    let expected = temp_dir
        .path()
        .join("_storage/logs")
        .display()
        .to_string();
    assert_eq!(log_directory, Some(expected));
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
async fn the_redis_stand_in_records_what_a_redis_client_adds_to_a_stream() {
    use redis::AsyncCommands;
    let stand_in = bdd_support::redis_stream::RedisStreamStandIn::start().await;
    let client = redis::Client::open(stand_in.url()).unwrap();
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .unwrap();

    let id: String = connection
        .xadd("sign-ins", "*", &[("data", r#"{"event_type":"user.login"}"#)])
        .await
        .unwrap();

    assert_eq!(id, "1-0");
    assert_eq!(
        stand_in.entries(),
        [bdd_support::redis_stream::StreamEntry {
            stream: "sign-ins".to_string(),
            fields: vec![("data".to_string(), r#"{"event_type":"user.login"}"#.to_string())],
        }]
    );
}

fn webauthn_for_localhost() -> webauthn_rs::prelude::Webauthn {
    webauthn_rs::prelude::WebauthnBuilder::new("localhost", &url::Url::parse("http://localhost:32001").unwrap())
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn a_registered_soft_passkey_signs_in_and_an_unregistered_one_is_refused() {
    use bdd_support::passkey::SoftPasskey;
    let webauthn = webauthn_for_localhost();
    let mut passkey = SoftPasskey::new("localhost", "http://localhost:32001");
    let (creation, registration) = webauthn
        .start_passkey_registration(uuid::Uuid::new_v4(), "alpha", "alpha", None)
        .unwrap();
    let credential = passkey.register(&serde_json::to_value(&creation).unwrap());
    let registered = webauthn
        .finish_passkey_registration(&serde_json::from_value(credential).unwrap(), &registration)
        .expect("the registration verifies");

    let (request, authentication) = webauthn
        .start_passkey_authentication(std::slice::from_ref(&registered))
        .unwrap();
    let request = serde_json::to_value(&request).unwrap();
    let signed = webauthn.finish_passkey_authentication(
        &serde_json::from_value(passkey.sign_in(&request)).unwrap(),
        &authentication,
    );
    let mut unregistered = SoftPasskey::new("localhost", "http://localhost:32001");
    let (request, authentication) = webauthn
        .start_passkey_authentication(std::slice::from_ref(&registered))
        .unwrap();
    let refused = webauthn.finish_passkey_authentication(
        &serde_json::from_value(unregistered.sign_in(&serde_json::to_value(&request).unwrap())).unwrap(),
        &authentication,
    );

    assert!(signed.is_ok(), "{signed:?}");
    assert!(refused.is_err());
}
