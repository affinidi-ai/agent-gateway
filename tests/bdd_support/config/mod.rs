use std::fmt::Debug;
use std::fs::OpenOptions;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};

pub mod a2a_proxy;
pub mod agent_surface;
pub mod api_keys;
pub mod config_tree;
pub mod dev_certs;
pub mod fabric_gateway_writer;
pub mod fabric_surface_fixture;
pub mod gateway_bootstrap;
pub mod jwt_verification_strategy;
pub mod managed_identity;
pub mod mcp_proxy;
pub mod policy_definitions;
pub mod secrets;
pub mod single_surface_fixture;
pub mod single_surface_writer;
pub mod source_auth;
pub mod storage;
pub mod target_auth;
pub mod toml;

pub(crate) const DEFAULT_HEADER_METADATA_EXTENSION_URI: &str =
    "https://fabric.affinidi.io/extensions/header-metadata/v1";

const TEST_PORT_MIN: usize = 20_000;
const TEST_PORT_MAX_EXCLUSIVE: usize = 30_000;
const TEST_PORT_RANGE: usize = TEST_PORT_MAX_EXCLUSIVE - TEST_PORT_MIN;

static NEXT_TEST_PORT_OFFSET: LazyLock<AtomicUsize> = LazyLock::new(|| {
    let process_offset = std::process::id() as usize % TEST_PORT_RANGE;
    AtomicUsize::new(process_offset)
});

pub struct ReservedPort {
    port_number: u16,
    reason: String,
    listener: Option<TcpListener>,
    lock_path: PathBuf,
}

impl ReservedPort {
    pub fn release_listener(&mut self) {
        self.listener.take();
    }

    pub fn port_number(&self) -> u16 {
        self.port_number
    }
}

impl Debug for ReservedPort {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        write!(f, "ReservedPort({}: {})", self.port_number, self.reason)
    }
}

impl Drop for ReservedPort {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

pub fn reserve_free_port(reason: &str) -> (u16, ReservedPort) {
    let lock_dir = std::env::temp_dir().join("agent-gateway-test-ports");
    std::fs::create_dir_all(&lock_dir).expect("create gateway test port lock dir");

    for _ in 0..TEST_PORT_RANGE {
        let offset = NEXT_TEST_PORT_OFFSET.fetch_add(1, Ordering::Relaxed) % TEST_PORT_RANGE;
        let port = TEST_PORT_MIN + offset;
        let lock_path = lock_dir.join(format!("{port}.lock"));
        let Ok(_lock_file) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        else {
            continue;
        };

        match TcpListener::bind(("0.0.0.0", port as u16)) {
            Ok(listener) => {
                return (
                    port as u16,
                    ReservedPort {
                        port_number: port as u16,
                        reason: reason.to_string(),
                        listener: Some(listener),
                        lock_path,
                    },
                );
            }
            Err(_) => {
                let _ = std::fs::remove_file(lock_path);
            }
        }
    }

    panic!("no available BDD gateway port in {TEST_PORT_MIN}..{TEST_PORT_MAX_EXCLUSIVE}");
}
