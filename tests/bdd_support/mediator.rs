//! Pluggable mediator abstraction.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::Value;
use tempfile::{Builder, TempDir};
use tokio::process::Command as TokioCommand;

use crate::bdd_support::config::{ReservedPort, reserve_free_port};

const MANAGED_MEDIATOR_ENV: &str = "FABRIC_BDD_MANAGED_MEDIATOR";
const MEDIATOR_PORT_ENV: &str = "FABRIC_BDD_MEDIATOR_PORT";
const LEGACY_MEDIATOR_PORT_ENV: &str = "G2G_MEDIATOR_PORT";
const PARALLELISM_ENV: &str = "G2G_BDD_PARALLELISM";
const BRIDGE_TARGET_HOST_ENV: &str = "G2G_MEDIATOR_BRIDGE_TARGET_HOST";
const DEFAULT_MEDIATOR_PORT: u16 = 7037;
const MEDIATOR_READY_TIMEOUT: Duration = Duration::from_secs(60);
static NEXT_MEDIATOR_ID: AtomicUsize = AtomicUsize::new(1);

/// What every Gateway instance needs to know about the mediator that relays its
/// gateway-to-gateway DIDComm traffic.
#[allow(dead_code)]
pub trait Mediator: std::fmt::Debug + Send + Sync {
    fn did(&self) -> &str;
    fn did_document(&self) -> Option<&Value>;
    fn did_method(&self) -> &str;

    /// Docker container name of the mediator, if the mediator is running as
    /// a Docker container. Returned by [`ScenarioDockerMediator`]; `None`
    /// for other transports. Consumers use this to attach sibling containers
    /// to the mediator's netns via `network_mode: container:<name>`.
    fn container_name(&self) -> Option<&str> {
        None
    }

    /// Docker-compose network name the mediator's compose project owns.
    /// Default empty string for transports that don't run under
    /// docker-compose.
    fn docker_network(&self) -> &str {
        ""
    }

    /// Port the mediator listens on **inside** its netns — what sibling
    /// containers using `network_mode: container:<mediator>` see on
    /// `127.0.0.1`. Default `0` for transports that don't publish a
    /// container-internal port.
    fn internal_port(&self) -> u16 {
        0
    }
}

#[derive(Debug)]
pub enum MediatorEnvCheck {
    Run,
    Skip(String),
}

#[derive(Debug)]
pub struct ScenarioDockerMediator {
    did: String,
    did_document: Value,
    did_method: String,
    compose_dir: PathBuf,
    label: String,
    network_name: String,
    port: u16,
    bridges: Vec<MediatorPortBridge>,
    _port_reservations: Vec<ReservedPort>,
    temp_dir: Option<TempDir>,
}

impl ScenarioDockerMediator {
    /// Returns Ok when the harness should manage one mediator per scenario;
    /// otherwise the test binary exits cleanly for local `cargo test` runs.
    pub fn validate_env(parallelism: usize) -> std::result::Result<MediatorEnvCheck, String> {
        if !managed_mediator_enabled() {
            return Ok(MediatorEnvCheck::Skip(format!(
                "Skipping g2g_bdd: set {MANAGED_MEDIATOR_ENV}=1 to run the per-scenario mediator suite \
             (e.g. via `make gw-e2e`)"
            )));
        }

        if parallelism > 1
            && let Some((name, value)) = fixed_mediator_port_env()
        {
            return Err(format!(
                "{PARALLELISM_ENV}={parallelism} requires per-scenario mediator ports, but {name}={value} fixes every scenario to one port; unset {name} or run with {PARALLELISM_ENV}=1"
            ));
        }

        Ok(MediatorEnvCheck::Run)
    }

    /// Path to the generated docker-compose directory for this mediator.
    /// Callers that need to tear the stack down out-of-band (e.g. an
    /// `atexit` cleanup that runs after `Drop` is skipped for a `static`
    /// holder) can shell out `docker compose -f <dir>/docker-compose.yml
    /// down -v`.
    pub fn compose_dir(&self) -> &Path {
        &self.compose_dir
    }

    pub async fn start() -> Result<Self> {
        Self::start_impl(false).await
    }

    /// Start the mediator on a dynamically-reserved free port, bypassing the
    /// fixed-port fast path `mediator_port` otherwise takes when
    /// `G2G_BDD_PARALLELISM` <= 1. Used to spin up a *second* independent
    /// mediator in the same test process (per-gateway mediator federation)
    /// so it never collides with a first mediator already bound to the
    /// default/fixed port.
    pub async fn start_with_free_port() -> Result<Self> {
        Self::start_impl(true).await
    }

    /// Empties the mediator's store while the mediator keeps running, so every
    /// account, session and access list it held is gone, as after a database
    /// flush or failover. Open WebSocket connections stay up.
    #[allow(dead_code)]
    pub async fn flush_store(&self) -> Result<()> {
        run_docker_compose(&self.compose_dir, &["exec", "-T", "redis", "valkey-cli", "FLUSHALL"])
            .await
            .with_context(|| format!("flush the store of mediator {}", self.label))
    }

    async fn start_impl(force_free_port: bool) -> Result<Self> {
        let parallelism = configured_parallelism().map_err(anyhow::Error::msg)?;
        let mut port = mediator_port(parallelism, force_free_port)?;
        let label =
            format!("g2g-bdd-mediator-{}-{}", std::process::id(), NEXT_MEDIATOR_ID.fetch_add(1, Ordering::Relaxed));
        let temp_dir = mediator_temp_dir(&label)?;
        let relative_dir = relative_to_repo(temp_dir.path())?
            .to_string_lossy()
            .to_string();

        generate_mediator_config(&relative_dir, port.number, &label).await?;

        // mediator-setup writes `mediator_did` into `conf/mediator.toml` and the
        // resolved DID document into the last JSONL entry of `conf/did.jsonl`
        // (`.state` field).
        let mediator_toml_path = temp_dir
            .path()
            .join("conf")
            .join("mediator.toml");
        let did = extract_did_from_toml(&mediator_toml_path)
            .with_context(|| format!("extract mediator DID from {}", mediator_toml_path.display()))?;
        let did_jsonl_path = temp_dir
            .path()
            .join("conf")
            .join("did.jsonl");
        let did_document = read_did_document_from_file(&did_jsonl_path)
            .with_context(|| format!("read mediator DID document from {}", did_jsonl_path.display()))?;
        let did_method = std::env::var("FABRIC_BDD_DID_METHOD").unwrap_or_else(|_| "peer".to_string());

        let bridge_target_host = mediator_bridge_target_host();
        port.release_listener();
        let bridges = match bridge_target_host {
            Some(target_host) => {
                // Bridge the mediator port so the same 127.0.0.1:<port> address
                // works from the CI job container.
                vec![MediatorPortBridge::start(port.number, &target_host, &label)?]
            }
            None => Vec::new(),
        };

        let mut reservations = Vec::with_capacity(1);
        if let Some(reservation) = port.reservation.take() {
            reservations.push(reservation);
        }

        let mediator = Self {
            did,
            did_document,
            did_method,
            compose_dir: temp_dir.path().to_path_buf(),
            network_name: format!("{label}_mediatornet"),
            label,
            port: port.number,
            bridges,
            _port_reservations: reservations,
            temp_dir: Some(temp_dir),
        };

        let _ = run_docker_compose(&mediator.compose_dir, &["down", "-v"])
            .await
            .map_err(|error| {
                eprintln!("[harness] {} docker compose down before start failed: {error:#}", mediator.label)
            });
        run_docker_compose(&mediator.compose_dir, &["up", "-d"])
            .await
            .with_context(|| format!("start mediator {} on port {}", mediator.label, mediator.port))?;
        wait_until_ready(mediator.port)
            .await
            .with_context(|| mediator.startup_diagnostics())?;

        Ok(mediator)
    }

    fn startup_diagnostics(&self) -> String {
        let bridges = if self.bridges.is_empty() {
            "no bridges".to_string()
        } else {
            let targets: Vec<String> = self
                .bridges
                .iter()
                .map(|bridge| bridge.target())
                .collect();
            format!("bridges [{}]", targets.join(", "))
        };
        format!(
            "mediator {} did not become ready; port={}, compose_dir={}, {}",
            self.label,
            self.port,
            self.compose_dir.display(),
            bridges
        )
    }
}

impl Mediator for ScenarioDockerMediator {
    fn did(&self) -> &str {
        &self.did
    }

    fn did_document(&self) -> Option<&Value> {
        Some(&self.did_document)
    }

    fn did_method(&self) -> &str {
        &self.did_method
    }

    /// `scripts/g2g-mediator.sh` names the mediator container after the
    /// compose project (`G2G_MEDIATOR_NAME`, set to this mediator's label).
    fn container_name(&self) -> Option<&str> {
        Some(&self.label)
    }

    fn docker_network(&self) -> &str {
        &self.network_name
    }

    fn internal_port(&self) -> u16 {
        self.port
    }
}

impl Drop for ScenarioDockerMediator {
    fn drop(&mut self) {
        self.bridges.clear();

        let down_status = Command::new("docker")
            .arg("compose")
            .arg("down")
            .arg("-v")
            .current_dir(&self.compose_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match down_status {
            Ok(status) if status.success() => {}
            Ok(status) => eprintln!("[harness] {} docker compose down exited with {status}", self.label),
            Err(error) => eprintln!("[harness] {} failed to run docker compose down: {error}", self.label),
        }

        if std::env::var("BDD_KEEP_TEMP_DIRS").is_ok()
            && let Some(temp_dir) = self.temp_dir.take()
        {
            let path = temp_dir.keep();
            eprintln!(
                "[harness] {} preserving mediator temp dir at {} (BDD_KEEP_TEMP_DIRS set)",
                self.label,
                path.display()
            );
        }
    }
}

struct MediatorPort {
    number: u16,
    reservation: Option<ReservedPort>,
}

impl MediatorPort {
    fn release_listener(&mut self) {
        if let Some(reservation) = self.reservation.as_mut() {
            reservation.release_listener();
        }
    }
}

struct MediatorPortBridge {
    port: u16,
    target_host: String,
    child: Mutex<Option<Child>>,
}

impl MediatorPortBridge {
    fn start(
        port: u16,
        target_host: &str,
        label: &str,
    ) -> Result<Self> {
        let child = Command::new("socat")
            .arg(format!("TCP-LISTEN:{port},fork,reuseaddr"))
            .arg(format!("TCP:{target_host}:{port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| {
                format!("start mediator port bridge for {label}: 127.0.0.1:{port} -> {target_host}:{port}")
            })?;

        Ok(Self {
            port,
            target_host: target_host.to_string(),
            child: Mutex::new(Some(child)),
        })
    }

    fn target(&self) -> String {
        format!("127.0.0.1:{} -> {}:{}", self.port, self.target_host, self.port)
    }
}

impl std::fmt::Debug for MediatorPortBridge {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("MediatorPortBridge")
            .field("port", &self.port)
            .field("target_host", &self.target_host)
            .finish_non_exhaustive()
    }
}

impl Drop for MediatorPortBridge {
    fn drop(&mut self) {
        let Ok(mut child) = self.child.lock() else {
            return;
        };
        if let Some(mut child) = child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Bridges cross-mediator relay traffic between two `ScenarioDockerMediator`
/// instances that each own an isolated Docker bridge network.
///
/// Per-gateway mediator federation gives every mediator its own compose
/// project and its own `<label>_mediatornet` bridge network, so a container
/// on mediator A's network cannot resolve mediator B's advertised
/// `http://localhost:<port>` service endpoint (that hostname/port only means
/// something inside B's own netns). The endpoint string itself cannot change:
/// it is baked into the peer mediator's DID document, and the mediator
/// software rejects relay traffic whose destination does not literally match
/// its own configured `local_endpoints` (self-authority matching).
///
/// The fix runs entirely at the network layer: a short-lived sidecar
/// container joins mediator A's netns via `network_mode: container:<A>` and
/// listens on `127.0.0.1:<B's port>` inside that shared netns, forwarding to
/// B's bridge-network gateway IP — which routes to the same Docker
/// daemon/host every mediator container publishes its port on. From inside
/// A's own container, `localhost:<B's port>` now resolves through the
/// sidecar to the real B. [`bridge_mediator_pairs`] wires one such sidecar
/// per ordered pair so relay works symmetrically. Uses a plain `alpine`
/// base with `socat` installed at start (rather than a third-party
/// pre-built socat image) to keep the pipeline's image surface to the same
/// well-known base already pulled by CI runners.
pub struct MediatorCrossBridge {
    sidecar_name: String,
}

impl MediatorCrossBridge {
    async fn start(
        attach_to_container: &str,
        attach_to_network: &str,
        peer_port: u16,
        label: &str,
    ) -> Result<Self> {
        let gateway_ip = network_gateway_ip(attach_to_network).await?;
        let sidecar_name = format!("{label}-xbridge-{peer_port}");

        // Clean up a stale sidecar from a prior failed run before starting a
        // fresh one under the same name.
        let _ = TokioCommand::new("docker")
            .args(["rm", "-f", &sidecar_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;

        let socat_cmd = format!(
            "apk add --no-cache socat >/dev/null 2>&1 && exec socat TCP-LISTEN:{peer_port},fork,reuseaddr TCP:{gateway_ip}:{peer_port}"
        );
        let output = TokioCommand::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                &sidecar_name,
                "--network",
                &format!("container:{attach_to_container}"),
                "alpine:3",
                "sh",
                "-c",
                &socat_cmd,
            ])
            .output()
            .await
            .with_context(|| format!("start mediator cross-bridge sidecar {sidecar_name}"))?;

        if !output.status.success() {
            bail!(
                "docker run failed for mediator cross-bridge sidecar {sidecar_name}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(Self { sidecar_name })
    }
}

impl std::fmt::Debug for MediatorCrossBridge {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("MediatorCrossBridge")
            .field("sidecar_name", &self.sidecar_name)
            .finish()
    }
}

impl Drop for MediatorCrossBridge {
    fn drop(&mut self) {
        let status = Command::new("docker")
            .args(["stop", "-t", "1", &self.sidecar_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if let Err(error) = status {
            eprintln!("[harness] failed to stop mediator cross-bridge sidecar {}: {error}", self.sidecar_name);
        }
    }
}

/// Resolves a Docker bridge network's gateway IP — the address any
/// container on that network uses to reach the host's other published
/// ports. Every mediator's isolated `mediatornet` routes through the same
/// underlying Docker daemon, so this IP works uniformly on Docker Desktop
/// and on Linux/dind (CI runners): no `host.docker.internal` DNS name is
/// required (which additionally cannot be combined with
/// `network_mode: container:*` at the Docker API level).
async fn network_gateway_ip(network: &str) -> Result<String> {
    let output = TokioCommand::new("docker")
        .args(["network", "inspect", network, "--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}"])
        .output()
        .await
        .with_context(|| format!("inspect docker network {network}"))?;

    if !output.status.success() {
        bail!("docker network inspect {network} failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let ip = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_string();
    if ip.is_empty() {
        bail!("docker network {network} has no gateway IP in its IPAM config");
    }
    Ok(ip)
}

/// Bridges every ordered pair of Docker-backed mediators so relay traffic
/// from one mediator's own container reaches its peer's real published
/// port instead of the sender's own loopback. A no-op for a single mediator
/// (the historical, most common case) and for any mediator transport that
/// does not run as a Docker container (`container_name()`/`docker_network()`
/// unset). See [`MediatorCrossBridge`] for why this is needed.
pub async fn bridge_mediator_pairs(mediators: &[&dyn Mediator]) -> Result<Vec<MediatorCrossBridge>> {
    let mut bridges = Vec::new();
    for (i, a) in mediators.iter().enumerate() {
        let (Some(a_name), a_network) = (a.container_name(), a.docker_network()) else {
            continue;
        };
        if a_network.is_empty() {
            continue;
        }
        for (j, b) in mediators.iter().enumerate() {
            if i == j || b.container_name().is_none() {
                continue;
            }
            let peer_port = b.internal_port();
            if peer_port == 0 {
                continue;
            }
            let label = format!("{a_name}-{j}");
            let bridge = MediatorCrossBridge::start(a_name, a_network, peer_port, &label).await?;
            bridges.push(bridge);
        }
    }
    Ok(bridges)
}

pub fn configured_parallelism() -> std::result::Result<usize, String> {
    match std::env::var(PARALLELISM_ENV) {
        Ok(value) => {
            let value = value.trim();
            value
                .parse::<usize>()
                .ok()
                .filter(|parallelism| *parallelism > 0)
                .ok_or_else(|| format!("{PARALLELISM_ENV} must be a positive integer, got {value:?}"))
        }
        Err(_) => Ok(1),
    }
}

pub fn managed_mediator_enabled() -> bool {
    std::env::var(MANAGED_MEDIATOR_ENV)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn fixed_mediator_port_env() -> Option<(&'static str, String)> {
    std::env::var(MEDIATOR_PORT_ENV)
        .ok()
        .map(|value| (MEDIATOR_PORT_ENV, value))
        .or_else(|| {
            std::env::var(LEGACY_MEDIATOR_PORT_ENV)
                .ok()
                .map(|value| (LEGACY_MEDIATOR_PORT_ENV, value))
        })
}

fn mediator_port(
    parallelism: usize,
    force_free_port: bool,
) -> Result<MediatorPort> {
    if parallelism > 1 || force_free_port {
        let (port, reservation) = reserve_free_port("g2g mediator");
        return Ok(MediatorPort {
            number: port,
            reservation: Some(reservation),
        });
    }

    match fixed_mediator_port_env() {
        Some((name, value)) => Ok(MediatorPort {
            number: value
                .parse::<u16>()
                .with_context(|| format!("parse {name}={value} as a TCP port"))?,
            reservation: None,
        }),
        None => Ok(MediatorPort {
            number: DEFAULT_MEDIATOR_PORT,
            reservation: None,
        }),
    }
}

fn mediator_bridge_target_host() -> Option<String> {
    std::env::var(BRIDGE_TARGET_HOST_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn mediator_temp_dir(label: &str) -> Result<TempDir> {
    let tmp_root = repo_root().join("tmp");
    std::fs::create_dir_all(&tmp_root).with_context(|| format!("create tmp dir at {}", tmp_root.display()))?;
    Builder::new()
        .prefix(label)
        .tempdir_in(&tmp_root)
        .with_context(|| format!("create mediator temp dir under {}", tmp_root.display()))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn relative_to_repo(path: &Path) -> Result<PathBuf> {
    path.strip_prefix(repo_root())
        .map(Path::to_path_buf)
        .with_context(|| format!("make {} relative to repo root", path.display()))
}

async fn generate_mediator_config(
    relative_dir: &str,
    port: u16,
    label: &str,
) -> Result<()> {
    let script = repo_root()
        .join("scripts")
        .join("g2g-mediator.sh");

    let output = TokioCommand::new(&script)
        .arg("--target-dir")
        .arg(relative_dir)
        .arg("--force")
        .env("G2G_MEDIATOR_DIR", relative_dir)
        .env("G2G_MEDIATOR_PORT", port.to_string())
        .env("G2G_MEDIATOR_NAME", label)
        .current_dir(repo_root())
        .output()
        .await
        .with_context(|| format!("run {}", script.display()))?;

    if !output.status.success() {
        bail!(
            "generate mediator config failed with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

async fn run_docker_compose(
    compose_dir: &Path,
    args: &[&str],
) -> Result<()> {
    let output = TokioCommand::new("docker")
        .arg("compose")
        .args(args)
        .current_dir(compose_dir)
        .output()
        .await
        .with_context(|| format!("docker compose {} in {}", args.join(" "), compose_dir.display()))?;

    if !output.status.success() {
        bail!(
            "docker compose {} failed with status {}\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

async fn wait_until_ready(port: u16) -> Result<()> {
    let addr = format!("127.0.0.1:{port}");
    let deadline = tokio::time::Instant::now() + MEDIATOR_READY_TIMEOUT;
    let mut last_error = None;

    while tokio::time::Instant::now() < deadline {
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(_) => return Ok(()),
            Err(error) => last_error = Some(error.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    bail!(
        "mediator at {addr} did not become ready within {:?}; last error: {}",
        MEDIATOR_READY_TIMEOUT,
        last_error.unwrap_or_else(|| "no response".to_string())
    )
}

/// Extract the mediator DID string from `conf/mediator.toml`. Mediator-setup
/// writes the line as `mediator_did = "did://did:webvh:..."`; we strip the
/// `did://` protocol prefix and return the bare `did:` string.
///
/// Mirrored from main's `tests/g2g_bdd/harness/mediator.rs::extract_did_from_toml`
/// so the two harnesses stay in lockstep.
fn extract_did_from_toml(path: &Path) -> Result<String> {
    let contents = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("mediator_did") {
            let rest = rest
                .trim()
                .strip_prefix('=')
                .unwrap_or(rest)
                .trim();
            let rest = rest.trim_matches('"');
            let did = rest
                .strip_prefix("did://")
                .unwrap_or(rest);
            if did.starts_with("did:") {
                return Ok(did.to_string());
            }
        }
    }
    bail!("mediator_did not found in {}", path.display())
}

/// Read the mediator DID document from the generated `conf/did.jsonl` file.
/// Parses the last non-empty JSONL entry's `state` field as the DID document.
///
/// Mirrored from main's `tests/g2g_bdd/harness/mediator.rs::read_did_document_from_file`.
fn read_did_document_from_file(path: &Path) -> Result<Value> {
    let contents = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let last_line = contents
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .with_context(|| format!("did.jsonl at {} is empty", path.display()))?;
    let entry: Value =
        serde_json::from_str(last_line).with_context(|| format!("parse last JSONL entry from {}", path.display()))?;
    entry
        .get("state")
        .cloned()
        .with_context(|| format!("no 'state' field in last JSONL entry of {}", path.display()))
}
