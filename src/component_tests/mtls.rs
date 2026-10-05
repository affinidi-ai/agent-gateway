//! Component tests for inbound mTLS source authentication.
//!
//! These tests stand up an in-process axum server that mirrors the
//! production listener wiring — `PeerCertAcceptor` (direct TLS handshake
//! peer-cert capture) plus the `promote_direct_peer_cert` and
//! `forwarded_peer_cert` middleware — against a real rustls TLS handshake
//! using a self-signed test PKI built with `rcgen`.
//!
//! Direct-TLS scenarios use raw `tokio-rustls` so we can assert specific
//! handshake outcomes (rejection by `WebPkiClientVerifier`, etc.) without
//! depending on reqwest's TLS feature set. The XFCC scenarios drive the
//! plain-HTTP path with an explicit `X-Forwarded-Client-Cert` header.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use axum::extract::Extension;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use dashmap::DashMap;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::json;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use crate::certificates::{
    Certificate, CertificateKind, CertificateStore, CreateCertificateRequest, FilesystemCertificateStore,
};
use crate::config::types::{ClientAuthConfig, DirectClientAuthMode, ForwardedHeaderConfig, ForwardedHeaderFormat};
use crate::didauth::DidAuthSessionStore;
use crate::jwt_bearer::{FileSystemJwtVerificationStrategyStore, JwksClient};
use crate::server::DirectClientAuth;
use crate::server::tls::load_server_config;
use crate::source_auth::SourceAuthMiddleware;
use crate::source_auth::models::{
    AuthenticatedIdentity, MtlsAuthConfig, MtlsIdentityBinding, MtlsTrust, PeerCertInfo, SourceAuthConfig,
};
use crate::source_auth::peer_cert::{PeerCertAcceptor, forwarded_peer_cert, promote_direct_peer_cert};

// ── one-shot rustls provider install ──────────────────────────────────────

fn ensure_rustls() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ── Test PKI builder ──────────────────────────────────────────────────────

struct TestPki {
    ca_pem: String,
    ca_der: CertificateDer<'static>,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
}

/// Build a self-signed CA, a server leaf (CN=localhost, SAN DNS:localhost +
/// IP:127.0.0.1) and a client leaf with the supplied common name.
fn build_pki(client_cn: &str) -> TestPki {
    // CA
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test mTLS CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_kp = KeyPair::generate().expect("ca keypair");
    let ca_cert = ca_params
        .clone()
        .self_signed(&ca_kp)
        .expect("self-signed ca");
    let ca_pem = ca_cert.pem();
    let ca_der = ca_cert.der().clone();
    let issuer = rcgen::Issuer::new(ca_params, ca_kp);

    // Server leaf
    let mut srv_params = CertificateParams::default();
    srv_params.distinguished_name = DistinguishedName::new();
    srv_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    srv_params.subject_alt_names = vec![
        SanType::DnsName(
            "localhost"
                .try_into()
                .unwrap(),
        ),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];
    srv_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let now = ::time::OffsetDateTime::now_utc();
    srv_params.not_before = now - ::time::Duration::seconds(60);
    srv_params.not_after = now + ::time::Duration::seconds(3600);
    let srv_kp = KeyPair::generate().expect("server keypair");
    let srv_cert = srv_params
        .signed_by(&srv_kp, &issuer)
        .expect("signed server");
    let server_cert_pem = srv_cert.pem();
    let server_key_pem = srv_kp.serialize_pem();

    // Client leaf
    let mut cli_params = CertificateParams::default();
    cli_params.distinguished_name = DistinguishedName::new();
    cli_params
        .distinguished_name
        .push(DnType::CommonName, client_cn);
    cli_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    cli_params.not_before = now - ::time::Duration::seconds(60);
    cli_params.not_after = now + ::time::Duration::seconds(3600);
    let cli_kp = KeyPair::generate().expect("client keypair");
    let cli_cert = cli_params
        .signed_by(&cli_kp, &issuer)
        .expect("signed client");
    let client_cert_pem = cli_cert.pem();
    let client_key_pem = cli_kp.serialize_pem();

    TestPki {
        ca_pem,
        ca_der,
        server_cert_pem,
        server_key_pem,
        client_cert_pem,
        client_key_pem,
    }
}

// ── Middleware/handler wiring ─────────────────────────────────────────────

fn identity_to_json(id: &AuthenticatedIdentity) -> serde_json::Value {
    match id {
        AuthenticatedIdentity::Mtls {
            principal,
            fingerprint,
            subject_dn,
            issuer_dn,
            sans,
            source,
        } => json!({
            "method": "mtls",
            "principal": principal,
            "fingerprint": fingerprint,
            "subject_dn": subject_dn,
            "issuer_dn": issuer_dn,
            "sans": sans,
            "source": match source {
                crate::source_auth::models::PeerCertSource::DirectTls => "direct_tls",
                crate::source_auth::models::PeerCertSource::Forwarded => "forwarded",
            },
        }),
        other => json!({ "method": "other", "debug": format!("{other:?}") }),
    }
}

#[derive(Clone)]
struct AuthState {
    middleware: Arc<SourceAuthMiddleware>,
    config: Arc<SourceAuthConfig>,
}

async fn auth_handler(
    Extension(state): Extension<AuthState>,
    headers: HeaderMap,
    req: axum::extract::Request,
) -> Response {
    let peer = req
        .extensions()
        .get::<PeerCertInfo>()
        .cloned();
    match state
        .middleware
        .authenticate(&state.config, &headers, "test-channel", "test-surface-id", peer.as_ref())
        .await
    {
        Ok(identity) => {
            (StatusCode::OK, Json(json!({ "ok": true, "identity": identity_to_json(&identity) }))).into_response()
        }
        Err(err) => (StatusCode::UNAUTHORIZED, Json(json!({ "ok": false, "error": err.to_string() }))).into_response(),
    }
}

async fn make_middleware() -> (Arc<SourceAuthMiddleware>, TempDir) {
    let tmp = TempDir::new().expect("tmp");
    let strategy_store = Arc::new(
        FileSystemJwtVerificationStrategyStore::new(
            tmp.path()
                .join("jwt_strategies"),
        )
        .await
        .expect("jwt strategy store"),
    );
    let didauth_store = Arc::new(DidAuthSessionStore::new());
    let jwks = Arc::new(JwksClient::new());
    let secrets_cache = Arc::new(DashMap::new());
    let mw = SourceAuthMiddleware::new(didauth_store, strategy_store, jwks, None, secrets_cache, None, None);
    (Arc::new(mw), tmp)
}

/// Seed a `FilesystemCertificateStore` with the test client cert
/// (`kind=ClientLeaf`) and CA (`kind=Ca`). Returns the IDs of each.
async fn seed_cert_store(pki: &TestPki) -> (Arc<dyn CertificateStore>, String, String, TempDir) {
    let tmp = TempDir::new().expect("tmp");
    let store = FilesystemCertificateStore::new(tmp.path().to_path_buf())
        .await
        .expect("cert store");

    let client_cert: Certificate = store
        .create(CreateCertificateRequest {
            tenant_id: None,
            name: "client".to_string(),
            description: None,
            tags: None,
            kind: CertificateKind::ClientLeaf,
            certificate_pem: pki.client_cert_pem.clone(),
            private_key_pem: None,
            expires_at: None,
            active: Some(true),
            identity_did: None,
        })
        .await
        .expect("create client cert");

    let ca_cert: Certificate = store
        .create(CreateCertificateRequest {
            tenant_id: None,
            name: "ca".to_string(),
            description: None,
            tags: None,
            kind: CertificateKind::Ca,
            certificate_pem: pki.ca_pem.clone(),
            private_key_pem: None,
            expires_at: None,
            active: Some(true),
            identity_did: None,
        })
        .await
        .expect("create ca");

    let store: Arc<dyn CertificateStore> = Arc::new(store);
    (store, client_cert.id, ca_cert.id, tmp)
}

async fn spawn_direct_tls_server(
    pki: &TestPki,
    middleware: Arc<SourceAuthMiddleware>,
    auth_cfg: SourceAuthConfig,
    direct_mode: DirectClientAuthMode,
) -> (SocketAddr, JoinHandle<()>, TempDir) {
    ensure_rustls();
    let tmp = TempDir::new().expect("tmp");
    let cert_path = tmp.path().join("server.crt");
    let key_path = tmp.path().join("server.key");
    std::fs::write(&cert_path, pki.server_cert_pem.as_bytes()).unwrap();
    std::fs::write(&key_path, pki.server_key_pem.as_bytes()).unwrap();

    let direct = DirectClientAuth {
        mode: direct_mode,
        ca_certs: vec![pki.ca_der.clone()],
    };
    let server_cfg = load_server_config(&cert_path, &key_path, Some(direct)).expect("server tls config");

    let client_auth_cfg = Arc::new(ClientAuthConfig {
        direct: direct_mode,
        trusted_proxies: vec![],
        forwarded_header: ForwardedHeaderConfig::default(),
    });

    let state = AuthState {
        middleware,
        config: Arc::new(auth_cfg),
    };

    let app = Router::new()
        .route("/auth", post(auth_handler))
        .layer(Extension(state))
        .layer(from_fn(promote_direct_peer_cert))
        .layer(from_fn_with_state(client_auth_cfg, forwarded_peer_cert));

    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener
        .set_nonblocking(true)
        .unwrap();
    let addr = std_listener
        .local_addr()
        .unwrap();

    let acceptor = PeerCertAcceptor::new(RustlsAcceptor::new(RustlsConfig::from_config(server_cfg)));

    let handle = tokio::spawn(async move {
        let _ = axum_server::from_tcp(std_listener)
            .expect("from_tcp")
            .acceptor(acceptor)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await;
    });

    // Give the server a beat to start accepting.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (addr, handle, tmp)
}

async fn spawn_plain_http_server(
    middleware: Arc<SourceAuthMiddleware>,
    auth_cfg: SourceAuthConfig,
    client_auth_cfg: ClientAuthConfig,
) -> (SocketAddr, JoinHandle<()>) {
    let state = AuthState {
        middleware,
        config: Arc::new(auth_cfg),
    };
    let app = Router::new()
        .route("/auth", post(auth_handler))
        .layer(Extension(state))
        .layer(from_fn(promote_direct_peer_cert))
        .layer(from_fn_with_state(Arc::new(client_auth_cfg), forwarded_peer_cert));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, handle)
}

// ── Raw HTTP-over-TLS client helpers ──────────────────────────────────────

fn parse_client_identity(pki: &TestPki) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let mut cert_rdr = std::io::BufReader::new(pki.client_cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_rdr)
        .collect::<Result<_, _>>()
        .expect("client certs");
    let mut key_rdr = std::io::BufReader::new(pki.client_key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_rdr)
        .expect("client key")
        .expect("non-empty");
    (certs, key)
}

fn build_client_config(
    pki: &TestPki,
    with_client_cert: bool,
) -> Arc<ClientConfig> {
    ensure_rustls();
    let mut roots = RootCertStore::empty();
    roots
        .add(pki.ca_der.clone())
        .unwrap();
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let cfg = if with_client_cert {
        let (certs, key) = parse_client_identity(pki);
        builder
            .with_client_auth_cert(certs, key)
            .expect("client auth cert")
    } else {
        builder.with_no_client_auth()
    };
    Arc::new(cfg)
}

/// Build a `ClientConfig` whose root store contains the *given* CA der but
/// whose client identity is signed by a *different* CA.
fn build_client_config_with_foreign_client_cert(
    server_pki: &TestPki,
    client_pki: &TestPki,
) -> Arc<ClientConfig> {
    ensure_rustls();
    let mut roots = RootCertStore::empty();
    roots
        .add(server_pki.ca_der.clone())
        .unwrap();
    let (certs, key) = parse_client_identity(client_pki);
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .expect("foreign client auth cert"),
    )
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    body: String,
}

async fn tls_post(
    addr: SocketAddr,
    client_cfg: Arc<ClientConfig>,
    host: &str,
    path: &str,
) -> std::io::Result<HttpResponse> {
    let tcp = TcpStream::connect(addr).await?;
    let connector = TlsConnector::from(client_cfg);
    let dns: ServerName<'static> = ServerName::try_from(host.to_string())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    let mut tls = connector
        .connect(dns, tcp)
        .await?;
    let req = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes())
        .await?;
    tls.flush().await?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf)
        .await?;
    parse_http_response(&buf)
}

fn parse_http_response(buf: &[u8]) -> std::io::Result<HttpResponse> {
    let text = String::from_utf8_lossy(buf).to_string();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or((text.as_str(), ""));
    let status_line = head
        .lines()
        .next()
        .unwrap_or("");
    let parts: Vec<&str> = status_line
        .splitn(3, ' ')
        .collect();
    let status: u16 = parts
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok(HttpResponse { status, body: body.to_string() })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn direct_tls_pinned_accepts_matching_client_cert() {
    let pki = build_pki("alice");
    let (cert_store, client_cert_id, _ca_id, _store_tmp) = seed_cert_store(&pki).await;
    let (middleware_base, _mw_tmp) = make_middleware().await;
    // Re-create middleware with the cert store (helper above doesn't accept one).
    let strategy_store = Arc::new(
        FileSystemJwtVerificationStrategyStore::new(
            _mw_tmp
                .path()
                .join("jwt_strategies_2"),
        )
        .await
        .expect("jwt strategy store"),
    );
    let middleware = Arc::new(SourceAuthMiddleware::new(
        Arc::new(DidAuthSessionStore::new()),
        strategy_store,
        Arc::new(JwksClient::new()),
        None,
        Arc::new(DashMap::new()),
        None,
        Some(cert_store.clone()),
    ));
    drop(middleware_base);

    let mtls = MtlsAuthConfig {
        trust: MtlsTrust::Pinned {
            certificate_ids: vec![client_cert_id],
        },
        identity_binding: MtlsIdentityBinding::SubjectCn,
        allowed_subjects: vec![],
        allow_forwarded: true,
    };

    let (addr, handle, _srv_tmp) =
        spawn_direct_tls_server(&pki, middleware, SourceAuthConfig::Mtls(mtls), DirectClientAuthMode::Optional).await;

    let client_cfg = build_client_config(&pki, true);
    let resp = tls_post(addr, client_cfg, "localhost", "/auth")
        .await
        .unwrap();
    assert_eq!(resp.status, 200, "body: {}", resp.body);
    let v: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["identity"]["method"], "mtls");
    assert_eq!(v["identity"]["principal"], "alice");

    handle.abort();
}

#[tokio::test]
async fn direct_tls_ca_chain_subject_cn_binding() {
    let pki = build_pki("bob");
    let (cert_store, _client_id, ca_id, _store_tmp) = seed_cert_store(&pki).await;

    let strategy_store_tmp = TempDir::new().unwrap();
    let strategy_store = Arc::new(
        FileSystemJwtVerificationStrategyStore::new(
            strategy_store_tmp
                .path()
                .to_path_buf(),
        )
        .await
        .unwrap(),
    );
    let middleware = Arc::new(SourceAuthMiddleware::new(
        Arc::new(DidAuthSessionStore::new()),
        strategy_store,
        Arc::new(JwksClient::new()),
        None,
        Arc::new(DashMap::new()),
        None,
        Some(cert_store),
    ));

    let mtls = MtlsAuthConfig {
        trust: MtlsTrust::Ca {
            ca_certificate_ids: vec![ca_id],
            require_client_auth_eku: true,
            check_crl: false,
            require_ocsp: false,
        },
        identity_binding: MtlsIdentityBinding::SubjectCn,
        allowed_subjects: vec!["bob".to_string()],
        allow_forwarded: true,
    };

    let (addr, handle, _srv_tmp) =
        spawn_direct_tls_server(&pki, middleware, SourceAuthConfig::Mtls(mtls), DirectClientAuthMode::Optional).await;

    let client_cfg = build_client_config(&pki, true);
    let resp = tls_post(addr, client_cfg, "localhost", "/auth")
        .await
        .unwrap();
    assert_eq!(resp.status, 200, "body: {}", resp.body);
    let v: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
    assert_eq!(v["identity"]["principal"], "bob");
    assert!(
        v["identity"]["issuer_dn"]
            .as_str()
            .unwrap()
            .contains("Test mTLS CA")
    );

    handle.abort();
}

#[tokio::test]
async fn direct_tls_rejects_when_client_omits_cert() {
    let pki = build_pki("eve");
    let (cert_store, _client_id, ca_id, _store_tmp) = seed_cert_store(&pki).await;

    let strategy_store_tmp = TempDir::new().unwrap();
    let strategy_store = Arc::new(
        FileSystemJwtVerificationStrategyStore::new(
            strategy_store_tmp
                .path()
                .to_path_buf(),
        )
        .await
        .unwrap(),
    );
    let middleware = Arc::new(SourceAuthMiddleware::new(
        Arc::new(DidAuthSessionStore::new()),
        strategy_store,
        Arc::new(JwksClient::new()),
        None,
        Arc::new(DashMap::new()),
        None,
        Some(cert_store),
    ));

    let mtls = MtlsAuthConfig {
        trust: MtlsTrust::Ca {
            ca_certificate_ids: vec![ca_id],
            require_client_auth_eku: true,
            check_crl: false,
            require_ocsp: false,
        },
        identity_binding: MtlsIdentityBinding::SubjectCn,
        allowed_subjects: vec![],
        allow_forwarded: true,
    };

    let (addr, handle, _srv_tmp) = spawn_direct_tls_server(
        &pki,
        middleware,
        SourceAuthConfig::Mtls(mtls),
        // Optional => handshake succeeds without a client cert; middleware
        // is responsible for rejecting.
        DirectClientAuthMode::Optional,
    )
    .await;

    let client_cfg = build_client_config(&pki, false);
    let resp = tls_post(addr, client_cfg, "localhost", "/auth")
        .await
        .unwrap();
    assert_eq!(resp.status, 401, "body: {}", resp.body);
    let v: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
    assert_eq!(v["ok"], false);

    handle.abort();
}

#[tokio::test]
async fn direct_tls_rejects_untrusted_ca_at_handshake() {
    // Server trusts PKI A. Client presents a cert signed by PKI B.
    let server_pki = build_pki("alice");
    let foreign_pki = build_pki("mallory");

    let (cert_store, _cid, ca_id, _store_tmp) = seed_cert_store(&server_pki).await;
    let strategy_store_tmp = TempDir::new().unwrap();
    let strategy_store = Arc::new(
        FileSystemJwtVerificationStrategyStore::new(
            strategy_store_tmp
                .path()
                .to_path_buf(),
        )
        .await
        .unwrap(),
    );
    let middleware = Arc::new(SourceAuthMiddleware::new(
        Arc::new(DidAuthSessionStore::new()),
        strategy_store,
        Arc::new(JwksClient::new()),
        None,
        Arc::new(DashMap::new()),
        None,
        Some(cert_store),
    ));

    let mtls = MtlsAuthConfig {
        trust: MtlsTrust::Ca {
            ca_certificate_ids: vec![ca_id],
            require_client_auth_eku: true,
            check_crl: false,
            require_ocsp: false,
        },
        identity_binding: MtlsIdentityBinding::SubjectCn,
        allowed_subjects: vec![],
        allow_forwarded: true,
    };

    // Required mode => the TLS layer itself must reject the foreign cert.
    let (addr, handle, _srv_tmp) =
        spawn_direct_tls_server(&server_pki, middleware, SourceAuthConfig::Mtls(mtls), DirectClientAuthMode::Required)
            .await;

    let client_cfg = build_client_config_with_foreign_client_cert(&server_pki, &foreign_pki);
    let result = tls_post(addr, client_cfg, "localhost", "/auth").await;
    // A handshake / connection error is the expected outcome; some platforms
    // surface it as Ok with empty body if the peer closes after the alert.
    match result {
        Err(_) => {}
        Ok(resp) => assert!(
            resp.status == 0 || resp.status >= 400,
            "expected handshake failure or error response, got {resp:?}",
        ),
    }

    handle.abort();
}

#[tokio::test]
async fn xfcc_happy_path_from_trusted_proxy() {
    let pki = build_pki("forwarded-client");
    let (cert_store, client_id, _ca_id, _store_tmp) = seed_cert_store(&pki).await;
    let strategy_store_tmp = TempDir::new().unwrap();
    let strategy_store = Arc::new(
        FileSystemJwtVerificationStrategyStore::new(
            strategy_store_tmp
                .path()
                .to_path_buf(),
        )
        .await
        .unwrap(),
    );
    let middleware = Arc::new(SourceAuthMiddleware::new(
        Arc::new(DidAuthSessionStore::new()),
        strategy_store,
        Arc::new(JwksClient::new()),
        None,
        Arc::new(DashMap::new()),
        None,
        Some(cert_store),
    ));

    let mtls = MtlsAuthConfig {
        trust: MtlsTrust::Pinned {
            certificate_ids: vec![client_id],
        },
        identity_binding: MtlsIdentityBinding::SubjectCn,
        allowed_subjects: vec![],
        allow_forwarded: true,
    };

    let client_auth = ClientAuthConfig {
        direct: DirectClientAuthMode::Disabled,
        trusted_proxies: vec![
            "127.0.0.1/32"
                .parse()
                .unwrap(),
        ],
        forwarded_header: ForwardedHeaderConfig {
            header_name: "x-forwarded-client-cert".to_string(),
            format: ForwardedHeaderFormat::UrlEncodedPem,
        },
    };

    let (addr, handle) = spawn_plain_http_server(middleware, SourceAuthConfig::Mtls(mtls), client_auth).await;

    let xfcc = urlencoding::encode(&pki.client_cert_pem).into_owned();
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/auth"))
        .header("x-forwarded-client-cert", xfcc)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["identity"]["principal"], "forwarded-client");
    assert_eq!(v["identity"]["source"], "forwarded");

    handle.abort();
}

#[tokio::test]
async fn xfcc_rejected_when_proxy_not_trusted() {
    let pki = build_pki("forwarded-client");
    let (cert_store, client_id, _ca_id, _store_tmp) = seed_cert_store(&pki).await;
    let strategy_store_tmp = TempDir::new().unwrap();
    let strategy_store = Arc::new(
        FileSystemJwtVerificationStrategyStore::new(
            strategy_store_tmp
                .path()
                .to_path_buf(),
        )
        .await
        .unwrap(),
    );
    let middleware = Arc::new(SourceAuthMiddleware::new(
        Arc::new(DidAuthSessionStore::new()),
        strategy_store,
        Arc::new(JwksClient::new()),
        None,
        Arc::new(DashMap::new()),
        None,
        Some(cert_store),
    ));

    let mtls = MtlsAuthConfig {
        trust: MtlsTrust::Pinned {
            certificate_ids: vec![client_id],
        },
        identity_binding: MtlsIdentityBinding::SubjectCn,
        allowed_subjects: vec![],
        allow_forwarded: true,
    };

    let client_auth = ClientAuthConfig {
        direct: DirectClientAuthMode::Disabled,
        // No trusted proxies => XFCC header must be ignored.
        trusted_proxies: vec![],
        forwarded_header: ForwardedHeaderConfig {
            header_name: "x-forwarded-client-cert".to_string(),
            format: ForwardedHeaderFormat::UrlEncodedPem,
        },
    };

    let (addr, handle) = spawn_plain_http_server(middleware, SourceAuthConfig::Mtls(mtls), client_auth).await;

    let xfcc = urlencoding::encode(&pki.client_cert_pem).into_owned();
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/auth"))
        .header("x-forwarded-client-cert", xfcc)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["ok"], false);

    handle.abort();
}
