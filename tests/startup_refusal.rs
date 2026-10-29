#[path = "bdd_support/mod.rs"]
mod bdd_support;

use std::collections::HashMap;
use std::io::Read;
use std::process::Child;
use std::time::{Duration, Instant};

use bdd_support::config::config_tree::GatewayBootstrapFixture;
use bdd_support::config::gateway_bootstrap::GatewayBootstrapSurface;
use bdd_support::config::reserve_free_port;
use bdd_support::gateway_process::{OutputMode, SURFACE_TEST_AUTH_TOKEN, spawn_gateway_binary};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

struct Outcome {
    exit_code: Option<i32>,
    log: String,
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_with_channel_prefix(prefix: &str) -> (Outcome, bool) {
    start_with_config(prefix, |_| {})
}

fn start_with_config(
    channel_prefix: &str,
    patch_gateway: impl FnOnce(&mut serde_json::Value),
) -> (Outcome, bool) {
    let (port, mut reservation) = reserve_free_port("startup refusal");
    let temp = tempfile::TempDir::new().expect("temp dir");
    let mut fixture = GatewayBootstrapFixture::new(
        port,
        "api",
        vec![GatewayBootstrapSurface::new("probe", "probe", channel_prefix)],
        "",
    );
    fixture.root_dir = Some(temp.path().to_path_buf());
    let config = fixture.write_config_files();
    let gateway_json = temp
        .path()
        .join("gateway.json");
    let mut gateway: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&gateway_json).expect("read gateway.json"))
            .expect("parse gateway.json");
    patch_gateway(&mut gateway);
    std::fs::write(&gateway_json, serde_json::to_string_pretty(&gateway).expect("serialize gateway.json"))
        .expect("write gateway.json");
    reservation.release_listener();

    let mut child = KillOnDrop(spawn_gateway_binary(
        &config,
        temp.path(),
        SURFACE_TEST_AUTH_TOKEN,
        OutputMode::GatewayLog,
        &HashMap::new(),
    ));
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let mut listening = false;
    let exit_code = loop {
        if let Some(status) = child
            .0
            .try_wait()
            .expect("poll gateway")
        {
            break status.code();
        }
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            listening = true;
            break None;
        }
        assert!(Instant::now() < deadline, "gateway neither exited nor listened within {STARTUP_TIMEOUT:?}");
        std::thread::sleep(Duration::from_millis(100));
    };

    let mut log = String::new();
    std::fs::File::open(
        temp.path()
            .join("gateway.log"),
    )
    .and_then(|mut f| f.read_to_string(&mut log))
    .expect("read gateway.log");
    (Outcome { exit_code, log }, listening)
}

#[test]
fn channel_prefix_at_protected_resource_metadata_path_stops_startup() {
    let (outcome, listening) = start_with_channel_prefix("/.well-known/oauth-protected-resource");

    assert!(!listening, "gateway must not listen:\n{}", outcome.log);
    assert_eq!(outcome.exit_code, Some(2), "log:\n{}", outcome.log);
    assert!(
        outcome
            .log
            .contains("prefix '/.well-known/oauth-protected-resource' collides with reserved route"),
        "log:\n{}",
        outcome.log
    );
}

#[test]
fn channel_prefix_under_protected_resource_metadata_path_stops_startup() {
    let (outcome, listening) = start_with_channel_prefix("/.well-known/oauth-protected-resource/mcp");

    assert!(!listening, "gateway must not listen:\n{}", outcome.log);
    assert_eq!(outcome.exit_code, Some(2), "log:\n{}", outcome.log);
    assert!(
        outcome
            .log
            .contains("prefix '/.well-known/oauth-protected-resource/mcp' collides with reserved route"),
        "log:\n{}",
        outcome.log
    );
}

#[test]
fn look_alike_prefixes_do_not_stop_startup() {
    for prefix in ["/.well-known/oauth-protected-resources", "/.well-known"] {
        let (outcome, listening) = start_with_channel_prefix(prefix);

        assert!(listening, "prefix {prefix} should start; exit {:?}, log:\n{}", outcome.exit_code, outcome.log);
        assert_eq!(outcome.exit_code, None);
        assert!(
            !outcome
                .log
                .contains("collides with reserved route"),
            "log:\n{}",
            outcome.log
        );
    }
}

const METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

fn assert_refused(
    outcome: &Outcome,
    listening: bool,
    prefix: &str,
) {
    assert!(!listening, "gateway must not listen:\n{}", outcome.log);
    assert_eq!(outcome.exit_code, Some(2), "log:\n{}", outcome.log);
    assert!(
        outcome
            .log
            .contains(&format!("prefix '{prefix}' collides with reserved route")),
        "log:\n{}",
        outcome.log
    );
}

#[test]
fn route_prefix_under_protected_resource_metadata_path_stops_startup() {
    let prefix = format!("{METADATA_PATH}/docs");
    let (outcome, listening) = start_with_config("/probe", |gateway| {
        gateway["routes"]["docs"] =
            serde_json::json!({ "type": "redirect", "prefix": prefix, "target": "https://docs.example" });
    });

    assert_refused(&outcome, listening, &prefix);
}

#[test]
fn mcp_proxy_prefix_at_protected_resource_metadata_path_stops_startup() {
    let (outcome, listening) = start_with_config("/probe", |gateway| {
        gateway["mcp_proxies"] = serde_json::json!([{ "id": "mcp", "name": "mcp", "prefix": METADATA_PATH }]);
    });

    assert_refused(&outcome, listening, METADATA_PATH);
}
