//! Shared test harness for channel E2E smoke tests.
//!
//! `GatewayHarness` starts an in-process gateway (via `run_axum_proxy`) against a
//! lightweight axum mock target server and exposes the channel listen address for
//! test assertions.

pub(crate) mod audit_events;
pub mod jwt;

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::extract::Request;
use axum::response::Response;
use axum::{Router, routing::any};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::auth::AuthMode;
use crate::config::agent_surface::AgentSurface;
use crate::config::{
    A2aConfig, BootstrapConfig, ConfigFilePaths, DIDCacheBootstrapConfig, EncryptionConfig, ExtensionInspectionConfig,
    FacilitatorMode, GatewayConfig, IntegrationConfig, LoggingConfig, McpConfig, OobConnectionConfig,
    ReconnectPolicyConfig, StoragePaths, TlsConfig, X402Headers,
};
use crate::rbac::RbacConfig;
use crate::server::run_axum_proxy;

/// Replace placeholder addresses on every surface with concrete URLs.
///
/// Patches `access_point.listen_address` and `target.endpoint` directly on the
/// surface so that `variants` and `default_variant_id` are preserved (the
/// `to_channel_mapping` projection drops them).
fn patch_surface_placeholders(
    surface: &mut AgentSurface,
    channel_port: u16,
    outbound_addr: Option<&str>,
    mock_url: &str,
) {
    surface
        .access_point
        .listen_address = format!("http://localhost:{}", channel_port);
    if surface.target.endpoint == "inbound_target_placeholder"
        || surface
            .target
            .endpoint
            .is_empty()
    {
        surface.target.endpoint = mock_url.to_string();
    }
    // Patch transit points directly on the surface.
    if let Some(ref mut transit) = surface.transit {
        if let Some(out) = outbound_addr
            && transit
                .outbound_listen_address
                .as_deref()
                == Some("outbound_port_placeholder")
        {
            transit.outbound_listen_address = Some(out.to_string());
        }
        for tp in &mut transit.points {
            if tp.target_endpoint == "outbound_target_placeholder" || tp.target_endpoint.is_empty() {
                tp.target_endpoint = mock_url.to_string();
            }
        }
    }
}

// ── rustls global initialisation ────────────────────────────────────────────

static RUSTLS: OnceLock<()> = OnceLock::new();

fn ensure_rustls() {
    RUSTLS.get_or_init(|| {
        // Ignore "already installed" errors in case the binary was also started.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

static TRACING: OnceLock<()> = OnceLock::new();

fn ensure_tracing() {
    TRACING.get_or_init(|| {
        // Install a stderr subscriber so that gateway tracing output is visible
        // when running `cargo test -- --nocapture` (or with RUST_LOG set).
        // Ignore the error in case another subscriber was already installed.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_writer(std::io::stderr)
            .with_test_writer()
            .try_init();
    });
}

// ── free-port helper ─────────────────────────────────────────────────────────

static NEXT_GATEWAY_TEST_PORT: AtomicUsize = AtomicUsize::new(20_000);
const GATEWAY_TEST_PORT_START: usize = 20_000;
const GATEWAY_TEST_PORT_END: usize = 30_000;

pub struct ReservedPort {
    listener: Option<std::net::TcpListener>,
    lock_path: PathBuf,
}

impl ReservedPort {
    pub fn release_listener(&mut self) {
        self.listener.take();
    }
}

impl Drop for ReservedPort {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

/// Bind to a deterministic non-ephemeral test port, then return the reservation.
/// The caller must keep the reservation alive until the real server has bound.
/// The lock file coordinates nextest's per-test processes; the listener reserves
/// the port from unrelated processes until the gateway is ready to bind.
pub fn free_port() -> (u16, ReservedPort) {
    let lock_dir = std::env::temp_dir().join("agent-gateway-test-ports");
    std::fs::create_dir_all(&lock_dir).expect("create gateway test port lock dir");

    for _ in GATEWAY_TEST_PORT_START..GATEWAY_TEST_PORT_END {
        let candidate = NEXT_GATEWAY_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let port = if candidate >= GATEWAY_TEST_PORT_END {
            let wrapped = GATEWAY_TEST_PORT_START;
            let _ = NEXT_GATEWAY_TEST_PORT.compare_exchange(
                candidate + 1,
                wrapped + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            wrapped
        } else {
            candidate
        };

        let lock_path = lock_dir.join(format!("{port}.lock"));
        let Ok(_lock_file) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        else {
            continue;
        };

        match std::net::TcpListener::bind(("0.0.0.0", port as u16)) {
            Ok(listener) => {
                return (
                    port as u16,
                    ReservedPort {
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

    panic!("no free gateway test ports in {GATEWAY_TEST_PORT_START}..{GATEWAY_TEST_PORT_END}");
}

// ── mock target server ───────────────────────────────────────────────────────

/// The details of a request received by the mock server.
#[derive(Clone, Debug)]
pub struct ReceivedRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

enum MockBody {
    Json(String),
    Streamed { content_type: &'static str, chunks: Vec<(Duration, String)> },
}

/// A running axum server that simply echoes back a configurable response.
/// It records every inbound request via a watch channel.
pub struct MockServer {
    pub addr: SocketAddr,
    /// Latest request received by the mock (updated on each request).
    pub last_request_rx: watch::Receiver<Option<ReceivedRequest>>,
    /// Total number of requests received by the mock.
    pub request_count: Arc<AtomicUsize>,
    _handle: tokio::task::JoinHandle<()>,
}

impl MockServer {
    /// Start the mock and return when the server is ready to accept connections.
    pub async fn start() -> Self {
        Self::start_with_response(r#"{"result":"ok"}"#).await
    }

    /// Start the mock with a custom response body returned for every request.
    pub async fn start_with_response(response_body: impl Into<String>) -> Self {
        Self::start_with_response_gate(MockBody::Json(response_body.into()), None).await
    }

    pub async fn start_paused(response_body: impl Into<String>) -> (Self, Arc<tokio::sync::Notify>) {
        let gate = Arc::new(tokio::sync::Notify::new());
        let server = Self::start_with_response_gate(MockBody::Json(response_body.into()), Some(gate.clone())).await;
        (server, gate)
    }

    /// Start the mock so every response sends each chunk after its delay and
    /// then holds the body open without ending it.
    pub async fn start_with_streamed_body(
        content_type: &'static str,
        chunks: Vec<(Duration, String)>,
    ) -> Self {
        Self::start_with_response_gate(MockBody::Streamed { content_type, chunks }, None).await
    }

    async fn start_with_response_gate(
        response_body: MockBody,
        gate: Option<Arc<tokio::sync::Notify>>,
    ) -> Self {
        let response_body = Arc::new(response_body);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = watch::channel(None);
        let tx = Arc::new(tx);
        let counter = Arc::new(AtomicUsize::new(0));

        // Build the request handler once and reuse it for both `/` and `/{*path}`
        // so the mock can be hit by gateways that strip the entire route prefix.
        let make_handler = || {
            let tx = Arc::clone(&tx);
            let response_body = Arc::clone(&response_body);
            let counter = Arc::clone(&counter);
            let gate = gate.clone();
            move |req: Request| {
                let tx = Arc::clone(&tx);
                let response_body = Arc::clone(&response_body);
                let counter = Arc::clone(&counter);
                let gate = gate.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let method = req.method().to_string();
                    let path = req.uri().path().to_string();
                    let headers: HashMap<String, String> = req
                        .headers()
                        .iter()
                        .filter_map(|(k, v)| {
                            v.to_str()
                                .ok()
                                .map(|v| (k.as_str().to_string(), v.to_string()))
                        })
                        .collect();
                    let body = axum::body::to_bytes(req.into_body(), usize::MAX)
                        .await
                        .unwrap_or_default();
                    let body_str = String::from_utf8_lossy(&body).to_string();
                    let _ = tx.send(Some(ReceivedRequest {
                        method,
                        path,
                        headers,
                        body: body_str,
                    }));
                    if let Some(gate) = gate {
                        gate.notified().await;
                    }
                    let (content_type, body) = match response_body.as_ref() {
                        MockBody::Json(body) => ("application/json", axum::body::Body::from(body.clone())),
                        MockBody::Streamed { content_type, chunks } => {
                            use futures::StreamExt;
                            let chunks = futures::stream::iter(chunks.clone())
                                .then(|(delay, chunk)| async move {
                                    tokio::time::sleep(delay).await;
                                    Ok::<_, std::io::Error>(chunk)
                                })
                                .chain(futures::stream::pending());
                            (*content_type, axum::body::Body::from_stream(chunks))
                        }
                    };
                    Response::builder()
                        .status(200)
                        .header("content-type", content_type)
                        .body(body)
                        .unwrap()
                }
            }
        };

        let app = Router::new()
            .route("/", any(make_handler()))
            .route("/{*path}", any(make_handler()));

        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .ok();
        });

        // Give the server a moment to bind.
        tokio::time::sleep(Duration::from_millis(50)).await;

        MockServer {
            addr,
            last_request_rx: rx,
            request_count: counter,
            _handle: handle,
        }
    }

    /// Start the mock with an artificial delay before responding.
    ///
    /// Useful for testing timeout behaviour: the handler sleeps for `delay`
    /// before returning the response body.
    pub async fn start_with_delay(
        delay: Duration,
        response_body: impl Into<String>,
    ) -> Self {
        let response_body: Arc<String> = Arc::new(response_body.into());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = watch::channel(None);
        let tx = Arc::new(tx);
        let counter = Arc::new(AtomicUsize::new(0));

        let app = Router::new().route(
            "/{*path}",
            any({
                let tx = Arc::clone(&tx);
                let response_body = Arc::clone(&response_body);
                let counter = Arc::clone(&counter);
                move |req: Request| {
                    let tx = Arc::clone(&tx);
                    let response_body = Arc::clone(&response_body);
                    let counter = Arc::clone(&counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        let method = req.method().to_string();
                        let path = req.uri().path().to_string();
                        let headers: HashMap<String, String> = req
                            .headers()
                            .iter()
                            .filter_map(|(k, v)| {
                                v.to_str()
                                    .ok()
                                    .map(|v| (k.as_str().to_string(), v.to_string()))
                            })
                            .collect();
                        let body = axum::body::to_bytes(req.into_body(), usize::MAX)
                            .await
                            .unwrap_or_default();
                        let body_str = String::from_utf8_lossy(&body).to_string();
                        let _ = tx.send(Some(ReceivedRequest {
                            method,
                            path,
                            headers,
                            body: body_str,
                        }));

                        // Simulate slow upstream agent
                        tokio::time::sleep(delay).await;

                        Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(
                                response_body
                                    .as_str()
                                    .to_owned(),
                            ))
                            .unwrap()
                    }
                }
            }),
        );

        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .ok();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        MockServer {
            addr,
            last_request_rx: rx,
            request_count: counter,
            _handle: handle,
        }
    }

    /// Start the mock with an updatable response body.
    ///
    /// Returns the `MockServer` and a `watch::Sender` that can be used to
    /// change the response body between requests.
    pub async fn start_with_response_channel(initial: impl Into<String>) -> (Self, watch::Sender<String>) {
        let (resp_tx, resp_rx) = watch::channel(initial.into());
        let resp_rx = Arc::new(resp_rx);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = watch::channel(None);
        let tx = Arc::new(tx);
        let counter = Arc::new(AtomicUsize::new(0));

        let app = Router::new().route(
            "/{*path}",
            any({
                let tx = Arc::clone(&tx);
                let resp_rx = Arc::clone(&resp_rx);
                let counter = Arc::clone(&counter);
                move |req: Request| {
                    let tx = Arc::clone(&tx);
                    let resp_rx = Arc::clone(&resp_rx);
                    let counter = Arc::clone(&counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        let method = req.method().to_string();
                        let path = req.uri().path().to_string();
                        let headers: HashMap<String, String> = req
                            .headers()
                            .iter()
                            .filter_map(|(k, v)| {
                                v.to_str()
                                    .ok()
                                    .map(|v| (k.as_str().to_string(), v.to_string()))
                            })
                            .collect();
                        let body = axum::body::to_bytes(req.into_body(), usize::MAX)
                            .await
                            .unwrap_or_default();
                        let body_str = String::from_utf8_lossy(&body).to_string();
                        let _ = tx.send(Some(ReceivedRequest {
                            method,
                            path,
                            headers,
                            body: body_str,
                        }));
                        let response_body = resp_rx.borrow().clone();
                        Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(response_body))
                            .unwrap()
                    }
                }
            }),
        );

        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .ok();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        (
            MockServer {
                addr,
                last_request_rx: rx,
                request_count: counter,
                _handle: handle,
            },
            resp_tx,
        )
    }

    /// URL that clients (or the gateway) should forward requests to.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

// ── gateway config builders ──────────────────────────────────────────────────

/// Directory holding the TLS pair component tests boot the gateway with.
///
/// Prefers the pair `make config-certs` writes to `envs/certs`, and otherwise self-signs one into a
/// temporary directory so a fresh clone can run the suite without a certificate setup step. The
/// `TempDir` is held in a process-wide `OnceLock` because dropping it deletes the files while the
/// gateway is still reading them.
fn dev_cert_dir() -> PathBuf {
    static GENERATED_CERTS: OnceLock<TempDir> = OnceLock::new();

    let existing = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("envs/certs");
    dev_cert_dir_or_generate(&existing, &GENERATED_CERTS)
}

fn dev_cert_dir_or_generate(
    existing: &std::path::Path,
    generated: &OnceLock<TempDir>,
) -> PathBuf {
    if dev_cert_pair_present(existing) {
        return existing.to_path_buf();
    }

    generated
        .get_or_init(|| {
            let dir = tempfile::Builder::new()
                .prefix("agent-gateway-component-certs-")
                .tempdir()
                .expect("create temporary component test TLS directory");
            write_self_signed_cert_pair(dir.path());
            dir
        })
        .path()
        .to_path_buf()
}

fn dev_cert_pair_present(dir: &std::path::Path) -> bool {
    ["cert.pem", "key.pem"]
        .iter()
        .all(|name| std::fs::metadata(dir.join(name)).is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0))
}

fn write_self_signed_cert_pair(dir: &std::path::Path) {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.subject_alt_names = vec![
        SanType::DnsName(
            "localhost"
                .try_into()
                .expect("localhost is a valid DNS SAN"),
        ),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    ];

    let key = KeyPair::generate().expect("generate component test TLS key");
    let cert = params
        .self_signed(&key)
        .expect("self-sign component test TLS certificate");

    std::fs::write(dir.join("cert.pem"), cert.pem()).expect("write component test TLS certificate");
    std::fs::write(dir.join("key.pem"), key.serialize_pem()).expect("write component test TLS key");
}

#[test]
fn missing_dev_cert_pair_uses_process_temporary_material() {
    let absent = tempfile::tempdir()
        .unwrap()
        .path()
        .join("missing");
    let generated = OnceLock::new();

    let cert_dir = dev_cert_dir_or_generate(&absent, &generated);

    assert_ne!(cert_dir, absent);
    assert!(dev_cert_pair_present(&cert_dir));
}

#[test]
fn existing_dev_cert_pair_is_preferred() {
    let existing = tempfile::tempdir().unwrap();
    std::fs::write(
        existing
            .path()
            .join("cert.pem"),
        "existing cert",
    )
    .unwrap();
    std::fs::write(
        existing
            .path()
            .join("key.pem"),
        "existing key",
    )
    .unwrap();
    let generated = OnceLock::new();

    let cert_dir = dev_cert_dir_or_generate(existing.path(), &generated);

    assert_eq!(cert_dir, existing.path());
    assert!(generated.get().is_none());
}

/// Write a minimal `NetworkConfig` JSON file to `dir/gateway.json`.
/// The listener is configured for plain HTTP on `channel_port`.
/// If `outbound_port` is given, a second listener with `listener_type: "outbound"` is added.
fn write_gateway_json(
    dir: &std::path::Path,
    channel_port: u16,
    outbound_port: Option<u16>,
) -> PathBuf {
    let mut listeners = vec![serde_json::json!({
        "id": "smoke-test",
        "name": "Smoke Test",
        "bind_address": "0.0.0.0",
        "port": channel_port,
        "protocol": "http",
        "external_urls": [ format!("http://localhost:{}", channel_port) ]
    })];

    if let Some(ob_port) = outbound_port {
        listeners.push(serde_json::json!({
            "id": "smoke-test-outbound",
            "name": "Smoke Test Outbound",
            "bind_address": "127.0.0.1",
            "port": ob_port,
            "protocol": "http",
            "external_urls": [ format!("http://localhost:{}", ob_port) ],
            "listener_type": "outbound"
        }));
    }

    let json = serde_json::json!({
        "did": { "domain": "localhost" },
        "webauthn": {
            "rp_id": "localhost",
            "external_origin": format!("http://localhost:{}", channel_port)
        },
        "integration": { "types": [], "categories": [] },
        "listeners": listeners,
        "channels": [
            { "id": "smoke-test", "name": "smoke-test", "prefix": "/smoke" }
        ],
        "routes": {}
    });

    let path = dir.join("gateway.json");
    std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    path
}

/// Build a `BootstrapConfig` pointing entirely at `temp_dir`.
fn build_bootstrap_config(
    temp_dir: &TempDir,
    gateway_json: PathBuf,
) -> BootstrapConfig {
    let base = temp_dir.path();
    let certs = dev_cert_dir();

    BootstrapConfig {
        channel_config_source: "local".to_string(),
        dynamodb_table: None,
        aws_region: None,
        aws_profile: None,
        tls: TlsConfig {
            cert_path: certs.join("cert.pem"),
            key_path: certs.join("key.pem"),
            verify_upstream: false,
            client_auth: Default::default(),
        },
        encryption: EncryptionConfig::default(),
        a2a: A2aConfig::default(),
        mcp: McpConfig::default(),
        oob_connection: OobConnectionConfig::default(),
        reconnect_policy: ReconnectPolicyConfig::default(),
        logging: LoggingConfig {
            level: "error".to_string(),
            log_directory: Some(
                base.join("logs")
                    .to_string_lossy()
                    .into_owned(),
            ),
            ..LoggingConfig::default()
        },
        extension_inspection: ExtensionInspectionConfig::default(),
        rbac: RbacConfig::default(),
        did_cache: DIDCacheBootstrapConfig {
            storage_path: base
                .join("did_cache")
                .to_string_lossy()
                .into_owned(),
            ..DIDCacheBootstrapConfig::default()
        },
        config_files: ConfigFilePaths {
            gateway: gateway_json
                .to_string_lossy()
                .into_owned(),
            ..Default::default()
        },
        storage_paths: StoragePaths {
            config_cache: base
                .join("cache")
                .to_string_lossy()
                .into_owned(),
            identities: base
                .join("identities")
                .to_string_lossy()
                .into_owned(),
            settings: base
                .join("settings")
                .to_string_lossy()
                .into_owned(),
            vc_keys: base
                .join("vc_keys")
                .to_string_lossy()
                .into_owned(),
            terms: base
                .join("terms")
                .to_string_lossy()
                .into_owned(),
            secrets: base
                .join("secrets")
                .to_string_lossy()
                .into_owned(),
            apikeys: base
                .join("apikeys")
                .to_string_lossy()
                .into_owned(),
            certificates: base
                .join("certificates")
                .to_string_lossy()
                .into_owned(),
            gateways: base
                .join("gateways")
                .to_string_lossy()
                .into_owned(),
            mediators: base
                .join("mediators")
                .to_string_lossy()
                .into_owned(),
            trust_registries: base
                .join("trust_registries")
                .to_string_lossy()
                .into_owned(),
            notifications: base
                .join("notifications")
                .to_string_lossy()
                .into_owned(),
            notification_templates: base
                .join("notifications/templates")
                .to_string_lossy()
                .into_owned(),
            connection_points: base
                .join("connection_points")
                .to_string_lossy()
                .into_owned(),
            mcp_proxies: base
                .join("mcp_proxies")
                .to_string_lossy()
                .into_owned(),
            a2a_proxies: base
                .join("a2a_proxies")
                .to_string_lossy()
                .into_owned(),
            integrations: base
                .join("integrations/definitions")
                .to_string_lossy()
                .into_owned(),
            integration_triggers: base
                .join("integrations/triggers")
                .to_string_lossy()
                .into_owned(),
            webhooks: base
                .join("webhooks")
                .to_string_lossy()
                .into_owned(),
            metrics: base
                .join("metrics")
                .to_string_lossy()
                .into_owned(),
            passkeys: base
                .join("passkeys")
                .to_string_lossy()
                .into_owned(),
            avatars: base
                .join("avatars")
                .to_string_lossy()
                .into_owned(),
            messages: base
                .join("messages")
                .to_string_lossy()
                .into_owned(),
            x402_transactions: base
                .join("x402_transactions")
                .to_string_lossy()
                .into_owned(),
            mpp_transactions: base
                .join("mpp_transactions")
                .to_string_lossy()
                .into_owned(),
            sessions: base
                .join("sessions")
                .to_string_lossy()
                .into_owned(),
            system_metrics: base
                .join("system_metrics")
                .to_string_lossy()
                .into_owned(),
            policy_definitions: base
                .join("policy_definitions")
                .to_string_lossy()
                .into_owned(),
            global_policies: base
                .join("global_policies")
                .to_string_lossy()
                .into_owned(),
            issuers: base
                .join("issuers")
                .to_string_lossy()
                .into_owned(),
            authorities: base
                .join("authorities")
                .to_string_lossy()
                .into_owned(),
            credential_providers: base
                .join("credential_providers")
                .to_string_lossy()
                .into_owned(),
            delegation_vault: base
                .join("delegation_vault")
                .to_string_lossy()
                .into_owned(),
            agent_surfaces: base
                .join("agent_surfaces")
                .to_string_lossy()
                .into_owned(),
            agent_surface_templates: base
                .join("agent_surface_templates")
                .to_string_lossy()
                .into_owned(),
            backup_restore: base
                .join("backup_restore")
                .to_string_lossy()
                .into_owned(),
            identity_hash_pepper: base
                .join("identity_hash_pepper")
                .to_string_lossy()
                .into_owned(),
        },
        secrets_backend: "filesystem".to_string(),
        metrics_cache_ttl_seconds: 1,
        websocket_require_auth: false,
        session_timeout_minutes: 20,
        websocket_broadcast_buffer: 500,
        metrics_retention_minutes: 360,
        metrics_cache_ttl_seconds_legacy: 1,
        auth_mode: AuthMode::default(),
        // Deterministic literal test key (64-char hex); the field is required at runtime.
        backup_encryption_key: "00".repeat(32),
        legacy_backup_encryption_keys: None,
        trust_registry: Default::default(),
        tenancy: Default::default(),
        config_dir: None,
        server_mode: crate::server::mode::ServerMode::default(),
        cache_refresh_interval_secs: 0,
    }
}

/// Mount the identity API at `/api` on the gateway listener and seed an
/// approved administrator session. Returns a client that sends its bearer token.
/// Call from the harness `setup` closure, before the gateway boots.
pub fn configure_admin_api(bootstrap: &BootstrapConfig) -> reqwest::Client {
    let gateway_path = &bootstrap.config_files.gateway;
    let mut gateway: serde_json::Value = serde_json::from_slice(&std::fs::read(gateway_path).unwrap()).unwrap();
    gateway["routes"]["identity"] = serde_json::json!({"type": "identity_api", "prefix": "/api"});
    std::fs::write(gateway_path, serde_json::to_vec(&gateway).unwrap()).unwrap();
    let now = chrono::Utc::now();
    let user: crate::auth::storage::UserData = serde_json::from_value(serde_json::json!({
        "user_id": uuid::Uuid::new_v4().to_string(), "username": "component-test-admin",
        "passkeys": [], "role": "administrator", "status": "approved",
        "created_at": now, "updated_at": now
    }))
    .unwrap();
    let session = crate::auth::session::Session {
        token: uuid::Uuid::new_v4().to_string(),
        username: user.username.clone(),
        user_id: user.user_id.clone(),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(10),
        terms_gate: Default::default(),
    };
    for (directory, id, record) in [
        (
            &bootstrap
                .storage_paths
                .passkeys,
            &user.user_id,
            serde_json::to_value(&user).unwrap(),
        ),
        (
            &bootstrap
                .storage_paths
                .sessions,
            &session.token,
            serde_json::to_value(&session).unwrap(),
        ),
    ] {
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(
            std::path::Path::new(directory).join(format!("{id}.json")),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
    }
    let mut authorization = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", session.token)).unwrap();
    authorization.set_sensitive(true);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::AUTHORIZATION, authorization);
    reqwest::Client::builder()
        .no_proxy()
        .default_headers(headers)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

/// Build a single `ChannelMapping` with placeholder addresses.
///
/// Uses JSON deserialization so serde defaults apply for every optional field,
/// avoiding the need to maintain all fields by hand across struct changes.
/// The harness patches `listen_address` and `target_endpoint` automatically
/// after the setup closure returns.
pub fn build_minimal_channel() -> AgentSurface {
    let mut surface: AgentSurface = serde_json::from_value(serde_json::json!({
        "name": "smoke-test",
        "description": "E2E smoke test channel",
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": "/smoke",
            "protocol": "a2a"
        },
        "target": {
            "endpoint": "inbound_target_placeholder"
        }
    }))
    .expect("build_minimal_channel: AgentSurface JSON");
    // A `default` variant is added so tests can exercise `$alias` URL routing
    // against the minimal fixture. Behaviour matches base routing since
    // overrides are empty.
    surface.variants = vec![
        serde_json::from_value(serde_json::json!({
            "id": "vc-default",
            "alias": "default",
            "name": "default",
            "description": "",
            "enabled": true,
            "overrides": {}
        }))
        .expect("build_minimal_channel: SurfaceVariant JSON"),
    ];
    surface.default_variant_id = Some("vc-default".to_string());
    surface
}

/// Build a minimal MCP [`AgentSurface`] for component tests.
///
/// Identical to [`build_minimal_channel`] but with `protocol = "mcp"`. The
/// harness patches `listen_address` and `target_endpoint` automatically.
pub fn build_minimal_mcp_surface() -> AgentSurface {
    let mut surface: AgentSurface = serde_json::from_value(serde_json::json!({
        "name": "smoke-test",
        "description": "E2E smoke test MCP surface",
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": "/smoke",
            "protocol": "mcp"
        },
        "target": {
            "endpoint": "inbound_target_placeholder"
        }
    }))
    .expect("build_minimal_mcp_surface: AgentSurface JSON");
    surface.variants = vec![
        serde_json::from_value(serde_json::json!({
            "id": "vc-default",
            "alias": "default",
            "name": "default",
            "description": "",
            "enabled": true,
            "overrides": {}
        }))
        .expect("build_minimal_mcp_surface: SurfaceVariant JSON"),
    ];
    surface.default_variant_id = Some("vc-default".to_string());
    surface
}

/// Build a `ChannelMapping` with two virtual-channel variants:
/// * `default` — enabled, used when no `$alias` suffix is present
/// * `dev`     — disabled, used to exercise the disabled-variant 404 path
///
/// Both variants forward to the same target placeholder; the harness patches
/// the address in after the setup closure returns.
pub fn build_channel_with_disabled_variant() -> AgentSurface {
    let json = serde_json::json!({
        "surface_id": "smoke-test-variants",
        "name": "smoke-test-variants",
        "description": "E2E channel with one disabled variant",
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": "/smoke",
            "protocol": "a2a"
        },
        "target": {
            "endpoint": "inbound_target_placeholder"
        },
        "variants": [
            {
                "id": "vc-default",
                "alias": "default",
                "name": "default",
                "description": "",
                "enabled": true,
                "overrides": {}
            },
            {
                "id": "vc-dev",
                "alias": "dev",
                "name": "dev",
                "description": "",
                "enabled": false,
                "overrides": {}
            }
        ],
        "default_variant_id": "vc-default"
    });
    serde_json::from_value(json).expect("build_channel_with_disabled_variant: AgentSurface JSON")
}

/// Build a `ChannelMapping` with outbound enabled and a single outbound virtual channel.
///
/// The `outbound_listen_address` and `target_endpoint` are set to placeholders;
/// `GatewayHarness` patches them to the real addresses after the setup closure.
pub fn build_minimal_outbound_channel() -> AgentSurface {
    serde_json::from_value(serde_json::json!({
        "name": "smoke-outbound",
        "description": "E2E outbound smoke test channel",
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": "/smoke",
            "protocol": "a2a"
        },
        "target": {
            "endpoint": "inbound_target_placeholder"
        },
        "transit": {
            "outbound_listen_address": "outbound_port_placeholder",
            "points": [{
                "alias": "target",
                "target_endpoint": "outbound_target_placeholder",
                "gateway_url": "outbound_gateway_url_placeholder",
                "require_transit_token": false
            }]
        }
    }))
    .expect("build_minimal_outbound_channel: AgentSurface JSON")
}

/// Build a `ChannelMapping` with identity management enabled (inbound + outbound).
///
/// The channel has `managed_identity` set to `PayloadExtraction` with `meta_field: "agentIdentity"`.
/// Placeholder addresses are patched by `GatewayHarness`.
pub fn build_identity_channel() -> AgentSurface {
    let json = serde_json::json!({
        "name": "smoke-identity",
        "description": "E2E identity management test channel",
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": "/smoke",
            "protocol": "a2a"
        },
        "target": {
            "endpoint": "inbound_target_placeholder"
        },
        "transit": {
            "outbound_listen_address": "outbound_port_placeholder",
            "points": [{
                "alias": "target",
                "target_endpoint": "outbound_target_placeholder",
                "gateway_url": "outbound_gateway_url_placeholder",
                "require_transit_token": false,
                "identity_injection": { "inject_vp": true }
            }]
        },
        "identity_slots": {
            "protected": {
                "type": "payload_extraction",
                "meta_field": "agentIdentity",
                "extension_rules": {
                    "json_schema": {
                        "type": "object",
                        "properties": {
                            "softwareInfo": {
                                "type": "object",
                                "properties": {
                                    "name": { "type": "string", "x-identity": true },
                                    "version": { "type": "string", "x-identity": true }
                                }
                            },
                            "cloudProvider": { "type": "string", "x-identity": true }
                        }
                    }
                }
            }
        }
    });

    serde_json::from_value(json).expect("build_identity_channel: AgentSurface JSON")
}

/// Build a surface whose protected agent DID is derived from a credential
/// (`identity_slots.protected = from_api_key`).
///
/// `from_api_key` is credential-derived: the DID comes from a peppered HMAC of
/// the `api_key_id`, not from the response body, so no JSON schema is needed.
/// An `atgk_`-prefixed key derives directly without any store lookup, which
/// makes this the lightest e2e exercise of the credential-derived `Derived`
/// path through the proxy (the inbound counterpart to the unit tests in
/// `credential_identity.rs`).
pub fn build_api_key_identity_channel(api_key_id: &str) -> AgentSurface {
    let json = serde_json::json!({
        "name": "smoke-api-key-identity",
        "description": "E2E from_api_key managed identity test channel",
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": "/smoke",
            "protocol": "a2a"
        },
        "target": {
            "endpoint": "inbound_target_placeholder"
        },
        "transit": {
            "outbound_listen_address": "outbound_port_placeholder",
            "points": [{
                "alias": "target",
                "target_endpoint": "outbound_target_placeholder",
                "gateway_url": "outbound_gateway_url_placeholder",
                "require_transit_token": false
            }]
        },
        "identity_slots": {
            "protected": {
                "type": "from_api_key",
                "api_key_id": api_key_id
            }
        }
    });

    serde_json::from_value(json).expect("build_api_key_identity_channel: AgentSurface JSON")
}
///
/// The channel itself has NO `managed_identity` — the rule lives only on
/// the single outbound virtual channel (transit point). Used to verify
/// per-TP identity slot enforcement on the MA→TP outbound path.
pub fn build_per_tp_identity_channel() -> AgentSurface {
    let json = serde_json::json!({
        "name": "smoke-per-tp-identity",
        "description": "E2E per-TP identity management test channel",
        "access_point": {
            "listen_address": "inbound_port_placeholder",
            "route": "/smoke",
            "protocol": "a2a"
        },
        "target": {
            "endpoint": "inbound_target_placeholder"
        },
        "transit": {
            "outbound_listen_address": "outbound_port_placeholder",
            "points": [{
                "alias": "target",
                "target_endpoint": "outbound_target_placeholder",
                "gateway_url": "outbound_gateway_url_placeholder",
                "require_transit_token": false,
                "managed_identity": {
                    "type": "payload_extraction",
                    "meta_field": "agentIdentity",
                    "json_schema": {
                        "type": "object",
                        "properties": {
                            "agentIdentity": {
                                "type": "object",
                                "properties": {
                                    "fish": { "type": "string", "x-identity": true }
                                },
                                "required": ["fish"]
                            }
                        }
                    }
                }
            }]
        }
    });

    serde_json::from_value(json).expect("build_per_tp_identity_channel: AgentSurface JSON")
}

/// Build a `GatewayConfig` with an empty channel list.
fn build_gateway_config(bootstrap: &BootstrapConfig) -> GatewayConfig {
    GatewayConfig {
        surfaces: vec![],
        tls: bootstrap.tls.clone(),
        a2a: bootstrap.a2a.clone(),
        mcp: bootstrap.mcp.clone(),
        logging: bootstrap.logging.clone(),
        extension_inspection: bootstrap
            .extension_inspection
            .clone(),
        integration: IntegrationConfig {
            variable_pattern: r"\$\{([^:}]+)(?::([^}]+))?\}".to_string(),
            variable_pattern_description: None,
            custom_variable_prefix: "_".to_string(),
            types: vec![],
            categories: vec![],
        },
        facilitator_mode: FacilitatorMode::default(),
        x402_headers: X402Headers::default(),
    }
}

// ── GatewayHarness ───────────────────────────────────────────────────────────

/// A gateway server running on its own OS thread with a dedicated
/// multi-threaded Tokio runtime whose workers get an 8 MiB stack.
///
/// Production (`main.rs`) sets the same 8 MiB stack because `ssi-json-ld`'s
/// recursive expansion overflows the default 2 MiB Tokio worker stack while
/// minting agent-identity VPs. `#[tokio::test]` workers only get 2 MiB, so the
/// harness must serve gateway requests on matching 8 MiB workers or VP-minting
/// tests abort with a stack overflow (SIGABRT).
struct GatewayServer {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    _thread: std::thread::JoinHandle<()>,
}

impl GatewayServer {
    fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for GatewayServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn spawn_gateway_server(
    gw_config: GatewayConfig,
    bootstrap: BootstrapConfig,
) -> GatewayServer {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let thread = std::thread::Builder::new()
        .name("gw-harness".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(8 * 1024 * 1024)
                .build()
                .expect("build gateway harness runtime");
            rt.block_on(async move {
                tokio::select! {
                    result = run_axum_proxy(
                        gw_config,
                        bootstrap,
                    ) => {
                        if let Err(e) = result {
                            eprintln!("[GatewayHarness] gateway error: {e}");
                        }
                    }
                    _ = shutdown_rx => {}
                }
            });
        })
        .expect("spawn gateway harness thread");
    GatewayServer {
        shutdown: Some(shutdown_tx),
        _thread: thread,
    }
}

/// Holds a running in-process gateway and the associated mock target server.
///
/// When dropped the gateway task is aborted and the temp directory is removed.
pub struct GatewayHarness {
    /// HTTP base URL for the gateway channel, e.g. `http://127.0.0.1:PORT`.
    pub gateway_url: String,
    /// HTTP base URL for the gateway listener (host[:port], no path).
    /// Use this to test alternate paths (e.g. `$alias` suffixes).
    pub gateway_base: String,
    /// HTTP base URL for the outbound listener, if configured.
    pub outbound_url: Option<String>,
    /// The mock target that the gateway forwards to.
    pub mock: MockServer,
    _temp: TempDir,
    _port_guard: ReservedPort,
    _outbound_port_guard: Option<ReservedPort>,
    _gw_server: GatewayServer,
}

async fn wait_for_gateway_http(
    port: u16,
    label: &str,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let url = format!("http://127.0.0.1:{port}/v1/health");
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("build readiness HTTP client");

    loop {
        match client.get(&url).send().await {
            Ok(_) => break,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("{label} did not become HTTP-ready on port {port}: {e}"),
        }
    }
}

impl GatewayHarness {
    /// Boot the mock target and the gateway, wait until the channel port accepts
    /// connections, then return.
    ///
    /// `setup` receives the temp directory path, mutable references to the
    /// `GatewayConfig` and `BootstrapConfig`, and is called right before
    /// `run_axum_proxy`. Callers can use it to write fixture files to disk
    /// and/or tweak the channel / bootstrap configuration.
    pub async fn start<F>(setup: F) -> Self
    where
        F: FnOnce(&std::path::Path, &mut GatewayConfig, &mut BootstrapConfig),
    {
        ensure_rustls();
        ensure_tracing();

        let mock = MockServer::start().await;
        let (channel_port, mut port_guard) = free_port();

        let temp = tempfile::Builder::new()
            .prefix("ag-smoke-")
            .tempdir()
            .expect("tempdir");
        let gateway_json = write_gateway_json(temp.path(), channel_port, None);

        let mut bootstrap = build_bootstrap_config(&temp, gateway_json);
        let mut gw_config = build_gateway_config(&bootstrap);

        // Let the caller write fixture files and/or mutate configs.
        setup(temp.path(), &mut gw_config, &mut bootstrap);

        // Ensure every channel has its listen_address and target_endpoint
        // pointing at the test's mock server.
        let mock_url = mock.url();
        for surface in &mut gw_config.surfaces {
            patch_surface_placeholders(surface, channel_port, None, &mock_url);
        }

        // Release the listener so the gateway can bind, but keep the cross-process
        // reservation until readiness confirms this gateway owns the port.
        port_guard.release_listener();

        // Serialize this in-process gateway's boot against the mode-mutating unit
        // tests, which share the process-global server mode and hold `TEST_GUARD`.
        // Held across the boot so run_axum_proxy's is_standby() read is deterministic.
        let mode_boot_guard = crate::server::mode::TEST_GUARD
            .lock()
            .await;
        let gw_server = spawn_gateway_server(gw_config, bootstrap);

        wait_for_gateway_http(channel_port, "gateway").await;
        drop(mode_boot_guard);

        GatewayHarness {
            gateway_url: format!("http://127.0.0.1:{}/smoke/rpc", channel_port),
            gateway_base: format!("http://127.0.0.1:{}", channel_port),
            outbound_url: None,
            mock,
            _temp: temp,
            _port_guard: port_guard,
            _outbound_port_guard: None,
            _gw_server: gw_server,
        }
    }

    /// Same as [`start`] but uses a pre-created `MockServer` (e.g. one with
    /// an artificial delay) instead of spawning the default one.
    pub async fn start_with_mock<F>(
        mock: MockServer,
        setup: F,
    ) -> Self
    where
        F: FnOnce(&std::path::Path, &mut GatewayConfig, &mut BootstrapConfig),
    {
        ensure_rustls();
        ensure_tracing();

        let (channel_port, mut port_guard) = free_port();

        let temp = tempfile::Builder::new()
            .prefix("ag-smoke-")
            .tempdir()
            .expect("tempdir");
        let gateway_json = write_gateway_json(temp.path(), channel_port, None);

        let mut bootstrap = build_bootstrap_config(&temp, gateway_json);
        let mut gw_config = build_gateway_config(&bootstrap);

        setup(temp.path(), &mut gw_config, &mut bootstrap);

        let mock_url = mock.url();
        for surface in &mut gw_config.surfaces {
            patch_surface_placeholders(surface, channel_port, None, &mock_url);
        }

        port_guard.release_listener();

        // Serialize this in-process gateway's boot against the mode-mutating unit
        // tests (see `start`).
        let mode_boot_guard = crate::server::mode::TEST_GUARD
            .lock()
            .await;
        let gw_server = spawn_gateway_server(gw_config, bootstrap);

        wait_for_gateway_http(channel_port, "gateway").await;
        drop(mode_boot_guard);

        GatewayHarness {
            gateway_url: format!("http://127.0.0.1:{}/smoke/rpc", channel_port),
            gateway_base: format!("http://127.0.0.1:{}", channel_port),
            outbound_url: None,
            mock,
            _temp: temp,
            _port_guard: port_guard,
            _outbound_port_guard: None,
            _gw_server: gw_server,
        }
    }

    /// Boot the mock target and the gateway with an outbound listener, wait
    /// until both the inbound and outbound ports accept connections, then return.
    ///
    /// The `setup` closure works the same as [`start`](Self::start). The harness
    /// automatically patches `outbound_listen_address` and outbound virtual
    /// channel `target_endpoint` fields that are set to their placeholder values.
    pub async fn start_with_outbound<F>(setup: F) -> Self
    where
        F: FnOnce(&std::path::Path, &mut GatewayConfig, &mut BootstrapConfig),
    {
        ensure_rustls();
        ensure_tracing();

        let mock = MockServer::start().await;
        let (channel_port, mut port_guard) = free_port();
        let (outbound_port, mut outbound_port_guard) = free_port();

        let temp = tempfile::Builder::new()
            .prefix("ag-smoke-")
            .tempdir()
            .expect("tempdir");
        let gateway_json = write_gateway_json(temp.path(), channel_port, Some(outbound_port));

        let mut bootstrap = build_bootstrap_config(&temp, gateway_json);
        let mut gw_config = build_gateway_config(&bootstrap);

        // Let the caller write fixture files and/or mutate configs.
        setup(temp.path(), &mut gw_config, &mut bootstrap);

        // Patch inbound and outbound addresses on every channel.
        let outbound_addr = format!("http://localhost:{}", outbound_port);
        let mock_url = mock.url();
        for surface in &mut gw_config.surfaces {
            patch_surface_placeholders(surface, channel_port, Some(&outbound_addr), &mock_url);
        }

        // Release the listeners so the gateway can bind, but keep cross-process
        // reservations until readiness confirms this gateway owns the ports.
        port_guard.release_listener();
        outbound_port_guard.release_listener();

        // Serialize this in-process gateway's boot against the mode-mutating unit
        // tests (see `start`).
        let mode_boot_guard = crate::server::mode::TEST_GUARD
            .lock()
            .await;
        let gw_server = spawn_gateway_server(gw_config, bootstrap);

        wait_for_gateway_http(channel_port, "gateway").await;
        wait_for_gateway_http(outbound_port, "outbound listener").await;
        drop(mode_boot_guard);

        GatewayHarness {
            gateway_url: format!("http://127.0.0.1:{}/smoke/rpc", channel_port),
            gateway_base: format!("http://127.0.0.1:{}", channel_port),
            outbound_url: Some(format!("http://127.0.0.1:{}", outbound_port)),
            mock,
            _temp: temp,
            _port_guard: port_guard,
            _outbound_port_guard: Some(outbound_port_guard),
            _gw_server: gw_server,
        }
    }

    /// Like [`start_with_outbound`](Self::start_with_outbound) but accepts a
    /// pre-created [`MockServer`] so callers can configure custom response bodies.
    pub async fn start_with_outbound_mock<F>(
        mock: MockServer,
        setup: F,
    ) -> Self
    where
        F: FnOnce(&std::path::Path, &mut GatewayConfig, &mut BootstrapConfig),
    {
        ensure_rustls();
        ensure_tracing();

        let (channel_port, mut port_guard) = free_port();
        let (outbound_port, mut outbound_port_guard) = free_port();

        let temp = tempfile::Builder::new()
            .prefix("ag-smoke-")
            .tempdir()
            .expect("tempdir");
        let gateway_json = write_gateway_json(temp.path(), channel_port, Some(outbound_port));

        let mut bootstrap = build_bootstrap_config(&temp, gateway_json);
        let mut gw_config = build_gateway_config(&bootstrap);

        setup(temp.path(), &mut gw_config, &mut bootstrap);

        let outbound_addr = format!("http://localhost:{}", outbound_port);
        let mock_url = mock.url();
        for surface in &mut gw_config.surfaces {
            patch_surface_placeholders(surface, channel_port, Some(&outbound_addr), &mock_url);
        }

        port_guard.release_listener();
        outbound_port_guard.release_listener();

        // Serialize this in-process gateway's boot against the mode-mutating unit
        // tests (see `start`).
        let mode_boot_guard = crate::server::mode::TEST_GUARD
            .lock()
            .await;
        let gw_server = spawn_gateway_server(gw_config, bootstrap);

        wait_for_gateway_http(channel_port, "gateway").await;
        wait_for_gateway_http(outbound_port, "outbound listener").await;
        drop(mode_boot_guard);

        GatewayHarness {
            gateway_url: format!("http://127.0.0.1:{}/smoke/rpc", channel_port),
            gateway_base: format!("http://127.0.0.1:{}", channel_port),
            outbound_url: Some(format!("http://127.0.0.1:{}", outbound_port)),
            mock,
            _temp: temp,
            _port_guard: port_guard,
            _outbound_port_guard: Some(outbound_port_guard),
            _gw_server: gw_server,
        }
    }
}

impl Drop for GatewayHarness {
    fn drop(&mut self) {
        self._gw_server.shutdown();
    }
}
