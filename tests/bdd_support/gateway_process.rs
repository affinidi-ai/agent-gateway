use std::collections::HashMap;
use std::fmt::Debug;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{Result, bail};

use crate::bdd_support::config::ReservedPort;

pub const SURFACE_TEST_AUTH_TOKEN: &str = "surface-bdd-test-token-32-plus-chars";
pub const G2G_TEST_AUTH_TOKEN: &str = "g2g-bdd-test-token-32-plus-characters";

pub enum OutputMode {
    Piped,
    GatewayLog,
}

pub struct GatewayProcess {
    child: Child,
    pub port: u16,
    _port_reservation: Option<ReservedPort>,
}

impl Debug for GatewayProcess {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("GatewayProcess")
            .field("port", &self.port)
            .finish()
    }
}

impl GatewayProcess {
    pub fn start(
        config_path: &Path,
        base_folder: &Path,
        test_token: &str,
        output_mode: OutputMode,
    ) -> Self {
        Self::start_with_env(config_path, base_folder, test_token, output_mode, &HashMap::new())
    }

    pub fn start_with_env(
        config_path: &Path,
        base_folder: &Path,
        test_token: &str,
        output_mode: OutputMode,
        extra_env: &HashMap<String, String>,
    ) -> Self {
        let child = spawn_gateway_binary(config_path, base_folder, test_token, output_mode, extra_env);

        Self {
            child,
            port: 0,
            _port_reservation: None,
        }
    }

    pub fn start_surface(
        config_path: &Path,
        base_folder: &Path,
    ) -> Self {
        Self::start(config_path, base_folder, SURFACE_TEST_AUTH_TOKEN, OutputMode::GatewayLog)
    }

    pub fn start_surface_with_env(
        config_path: &Path,
        base_folder: &Path,
        extra_env: &HashMap<String, String>,
    ) -> Self {
        Self::start_with_env(config_path, base_folder, SURFACE_TEST_AUTH_TOKEN, OutputMode::Piped, extra_env)
    }

    pub fn start_g2g(
        config_path: &Path,
        base_folder: &Path,
    ) -> Self {
        Self::start(config_path, base_folder, G2G_TEST_AUTH_TOKEN, OutputMode::GatewayLog)
    }

    pub fn start_g2g_with_env(
        config_path: &Path,
        base_folder: &Path,
        extra_env: &HashMap<String, String>,
    ) -> Self {
        Self::start_with_env(config_path, base_folder, G2G_TEST_AUTH_TOKEN, OutputMode::GatewayLog, extra_env)
    }

    pub fn with_port(
        mut self,
        port: u16,
    ) -> Self {
        self.port = port;
        self
    }

    pub fn with_port_reservation(
        mut self,
        port_reservation: ReservedPort,
    ) -> Self {
        self._port_reservation = Some(port_reservation);
        self
    }

    pub async fn wait_until_ready(&mut self) {
        self.try_wait_until_ready(Duration::from_secs(60))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }

    pub async fn try_wait_until_ready(
        &mut self,
        timeout: Duration,
    ) -> Result<()> {
        wait_for_gateway_process(&mut self.child, self.port, timeout).await
    }

    /// Polls until a secondary listener of this same gateway process accepts a
    /// TCP connection, failing fast if the process exits before the port
    /// becomes ready instead of waiting out the full timeout.
    pub async fn wait_for_secondary_port(
        &mut self,
        port: u16,
        timeout: Duration,
    ) -> Result<()> {
        wait_for_gateway_process(&mut self.child, port, timeout).await
    }
}

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn spawn_gateway_binary(
    config_path: &Path,
    base_folder: &Path,
    test_token: &str,
    output_mode: OutputMode,
    extra_env: &HashMap<String, String>,
) -> Child {
    let binary = env!("CARGO_BIN_EXE_agent-gateway");
    let mut command = Command::new(binary);
    command
        .arg("--config")
        .arg(config_path)
        .arg("--base-folder")
        .arg(base_folder)
        .current_dir(base_folder)
        .env("AG_TEST_MODE", "true")
        .env("AG_TEST_TOKEN", test_token)
        .env("AG_TEST_ALLOW_ROLE_OVERRIDE", "true");

    for (name, value) in extra_env {
        command.env(name, value);
    }

    match output_mode {
        OutputMode::Piped => {
            command
                .stdout(Stdio::null())
                .stderr(Stdio::null());
        }
        OutputMode::GatewayLog => {
            // Append so a restarted gateway keeps the log of its first run.
            let log_path = base_folder.join("gateway.log");
            let log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .expect("open gateway.log");
            let log_clone = log_file
                .try_clone()
                .expect("clone gateway.log handle");
            command
                .stdout(Stdio::from(log_file))
                .stderr(Stdio::from(log_clone));
        }
    }

    command
        .spawn()
        .expect("failed to spawn gateway binary")
}

/// Polls until `port` accepts a TCP connection while watching `child`, failing
/// fast if the gateway process exits before the port becomes ready instead of
/// waiting out the full timeout.
async fn wait_for_gateway_process(
    child: &mut Child,
    port: u16,
    timeout: Duration,
) -> Result<()> {
    let addr = format!("127.0.0.1:{port}");
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            bail!("gateway process exited before becoming ready on port {port}: {status}");
        }

        match tokio::net::TcpStream::connect(&addr).await {
            Ok(_) => return Ok(()),
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => bail!("gateway did not become ready on port {port}: {e}"),
        }
    }
}
