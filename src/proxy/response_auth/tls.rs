//! The TLS settings of Response authentication by mTLS: a rustls client configuration that
//! trusts only the configured certificates, never the system's or public CAs, and presents the
//! gateway's client certificate when one is set.
//!
//! `pinned` trust accepts a server certificate whose SHA-256 fingerprint is that of a pinned
//! certificate, with no chain, name or expiry check, and still verifies the handshake signature
//! with that certificate's key. `ca` trust verifies the chain to one of the configured CAs and
//! the Target's host against the certificate's names. The settings are built once per surface
//! and setting, built again when a certificate the setting names changes, and dropped when the
//! surface changes or is deleted.

use std::sync::{Arc, LazyLock};

use dashmap::DashMap;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use tracing::warn;

use super::ResponseAuthFailure;
use crate::certificates::{Certificate, CertificateKind, CertificateStore};
use crate::config::agent_surface::AgentSurface;
use crate::config::response_auth::{MtlsResponseAuth, ResponseAuthConfig};
use crate::source_auth::models::MtlsTrust;

static SETTINGS: LazyLock<TlsSettingsCache> = LazyLock::new(TlsSettingsCache::default);

/// TLS settings built for a surface's Response authentication by mTLS, with the stamp of what
/// they were built from: the setting and every certificate it names, so the stamp changes when
/// a certificate is renewed.
#[derive(Clone)]
pub struct TargetTls {
    pub config: Arc<ClientConfig>,
    pub stamp: [u8; 32],
}

/// The TLS settings the gateway reaches `surface`'s Target with: `None` without Response
/// authentication by mTLS, and [`ResponseAuthFailure::Unverifiable`] when a certificate it names
/// cannot be used (missing, inactive, outside the surface's tenant, of the wrong kind, a client
/// certificate without its private key, or unreadable) or a CA trust asks for a revocation check.
pub async fn target_tls(
    surface: &AgentSurface,
    certificates: Option<&Arc<dyn CertificateStore>>,
) -> Result<Option<TargetTls>, ResponseAuthFailure> {
    SETTINGS
        .settings(surface, certificates)
        .await
}

/// Drops every mTLS setting built for the surface `surface_id`, so a changed or deleted surface
/// keeps no client configuration, and no client private key, in memory.
pub(crate) fn forget_tls_settings(surface_id: &str) {
    SETTINGS.forget(surface_id);
}

/// Drops every mTLS setting built for any surface, so a configuration reload keeps none built
/// from a surface it no longer serves as it was.
pub(crate) fn forget_all_tls_settings() {
    SETTINGS.forget_all();
}

/// [`ResponseAuthFailure::ServerUntrusted`] when `error`, from sending a request to the Target of
/// `surface`, is a TLS handshake whose server certificate failed the surface's mTLS server trust.
/// Any other error, a Target that cannot be reached among them, is `None`.
pub fn handshake_failure(
    surface: &AgentSurface,
    error: &reqwest::Error,
) -> Option<ResponseAuthFailure> {
    if !matches!(surface.target.response_auth, Some(ResponseAuthConfig::Mtls(_))) {
        return None;
    }
    std::iter::successors(Some(error as &(dyn std::error::Error + 'static)), |cause| cause.source())
        .find_map(rustls_error)
        .filter(|error| matches!(error, rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented))
        .map(|_| ResponseAuthFailure::ServerUntrusted)
}

/// The rustls error `error` is or wraps through I/O errors: the connector reports a failed
/// handshake as an I/O error wrapping the TLS stream's I/O error, which wraps the rustls error,
/// and `io::Error::source` skips those layers.
fn rustls_error<'a>(error: &'a (dyn std::error::Error + 'static)) -> Option<&'a rustls::Error> {
    let mut error = error;
    loop {
        if let Some(rustls) = error.downcast_ref::<rustls::Error>() {
            return Some(rustls);
        }
        error = error
            .downcast_ref::<std::io::Error>()?
            .get_ref()?;
    }
}

/// A surface's id and the hash of its mTLS setting, so each variant setting of a surface keeps
/// settings of its own.
type SettingKey = (String, [u8; 32]);

fn setting_key(
    surface: &AgentSurface,
    config: &MtlsResponseAuth,
) -> SettingKey {
    let setting = Sha256::digest(serde_json::to_vec(config).unwrap_or_default()).into();
    (surface.surface_id.clone(), setting)
}

/// The TLS settings built for each surface and setting, with the stamp of what they were built
/// from.
#[derive(Default)]
struct TlsSettingsCache {
    built: DashMap<SettingKey, ([u8; 32], Arc<ClientConfig>)>,
}

impl TlsSettingsCache {
    #[cfg(test)]
    fn stamp(
        &self,
        surface: &AgentSurface,
    ) -> Option<[u8; 32]> {
        let Some(ResponseAuthConfig::Mtls(config)) = surface
            .target
            .response_auth
            .as_ref()
        else {
            return None;
        };
        self.built
            .get(&setting_key(surface, config))
            .map(|built| built.0)
    }

    fn forget(
        &self,
        surface_id: &str,
    ) {
        self.built
            .retain(|(id, _), _| id != surface_id);
    }

    fn forget_all(&self) {
        self.built.clear();
    }

    async fn settings(
        &self,
        surface: &AgentSurface,
        certificates: Option<&Arc<dyn CertificateStore>>,
    ) -> Result<Option<TargetTls>, ResponseAuthFailure> {
        let Some(ResponseAuthConfig::Mtls(config)) = surface
            .target
            .response_auth
            .as_ref()
        else {
            return Ok(None);
        };
        let material = Material::load(surface, config, certificates).await?;
        let stamp = material.stamp(config);
        let key = setting_key(surface, config);
        if let Some(built) = self
            .built
            .get(&key)
            .filter(|built| built.0 == stamp)
        {
            return Ok(Some(TargetTls {
                config: Arc::clone(&built.1),
                stamp,
            }));
        }
        let built = Arc::new(material.client_config(config)?);
        self.built
            .insert(key, (stamp, Arc::clone(&built)));
        Ok(Some(TargetTls { config: built, stamp }))
    }
}

/// The certificates a surface's mTLS setting names, each checked usable by the surface.
struct Material {
    trust: Vec<Certificate>,
    client: Option<Certificate>,
}

impl Material {
    async fn load(
        surface: &AgentSurface,
        config: &MtlsResponseAuth,
        certificates: Option<&Arc<dyn CertificateStore>>,
    ) -> Result<Self, ResponseAuthFailure> {
        let unusable = |why: &str| {
            warn!(surface = %surface.surface_id, "Response authentication by mTLS cannot be used: {why}");
            ResponseAuthFailure::Unverifiable
        };
        let store = certificates.ok_or_else(|| unusable("the certificate store is unavailable"))?;
        let trust_kind = match &config.server_trust {
            MtlsTrust::Pinned { .. } => CertificateKind::ClientLeaf,
            MtlsTrust::Ca { check_crl, require_ocsp, .. } => {
                if *check_crl || *require_ocsp {
                    return Err(unusable("CRL and OCSP checks are not supported"));
                }
                CertificateKind::Ca
            }
        };
        let ids = config.trust_certificate_ids();
        if ids.is_empty() {
            return Err(unusable("the server trust names no certificate"));
        }
        let mut trust = Vec::with_capacity(ids.len());
        for id in ids {
            trust.push(usable(surface, store.as_ref(), id, trust_kind, false).await?);
        }
        let client = match config
            .client_certificate_id
            .as_deref()
        {
            Some(id) => {
                let certificate = usable(surface, store.as_ref(), id, CertificateKind::ClientLeaf, true).await?;
                if certificate
                    .private_key_pem
                    .as_deref()
                    .is_none_or(|key| key.trim().is_empty())
                {
                    return Err(unusable("the client certificate has no private key"));
                }
                Some(certificate)
            }
            None => None,
        };
        Ok(Self { trust, client })
    }

    /// What the settings are built from: the setting and every certificate it names, as stored.
    fn stamp(
        &self,
        config: &MtlsResponseAuth,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(config).unwrap_or_default());
        for certificate in self
            .trust
            .iter()
            .chain(&self.client)
        {
            hasher.update(certificate.id.as_bytes());
            hasher.update(
                certificate
                    .updated_at
                    .to_rfc3339(),
            );
            hasher.update(
                certificate
                    .certificate_pem
                    .as_bytes(),
            );
            hasher.update(
                certificate
                    .private_key_pem
                    .as_deref()
                    .unwrap_or_default(),
            );
        }
        hasher.finalize().into()
    }

    fn client_config(
        &self,
        config: &MtlsResponseAuth,
    ) -> Result<ClientConfig, ResponseAuthFailure> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|_| ResponseAuthFailure::Unverifiable)?;
        let builder = match &config.server_trust {
            MtlsTrust::Pinned { .. } => {
                let fingerprints = self
                    .trust
                    .iter()
                    .map(|certificate| leaf(certificate).map(|der| Sha256::digest(der.as_ref()).into()))
                    .collect::<Result<_, _>>()?;
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier { fingerprints, provider }))
            }
            MtlsTrust::Ca { .. } => {
                let mut roots = RootCertStore::empty();
                for certificate in &self.trust {
                    for der in chain(certificate)? {
                        roots
                            .add(der)
                            .map_err(|_| unreadable(certificate))?;
                    }
                }
                builder.with_root_certificates(roots)
            }
        };
        let mut tls = match &self.client {
            Some(certificate) => builder
                .with_client_auth_cert(chain(certificate)?, private_key(certificate)?)
                .map_err(|_| unreadable(certificate))?,
            None => builder.with_no_client_auth(),
        };
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(tls)
    }
}

/// `id` from `store`, when it is active, of `kind` and one `surface` may use. A certificate the
/// gateway `sent` is also held to `tenant_credential_isolation`, so under `enforce` a tenant
/// surface cannot present an appliance-wide client certificate.
async fn usable(
    surface: &AgentSurface,
    store: &dyn CertificateStore,
    id: &str,
    kind: CertificateKind,
    sent: bool,
) -> Result<Certificate, ResponseAuthFailure> {
    let may_reference = |certificate: &Certificate| {
        let (owner, referenced) = (
            surface.tenant_id.as_deref(),
            certificate
                .tenant_id
                .as_deref(),
        );
        if sent {
            crate::tenancy::can_reference_with_rule(
                owner,
                referenced,
                crate::config::credential_policy::credential_policy().tenant_credential_isolation,
            )
        } else {
            crate::tenancy::can_reference(owner, referenced)
        }
    };
    let why = match store.get(id).await {
        Ok(Some(certificate)) if !certificate.active => "it is inactive",
        Ok(Some(certificate)) if certificate.kind != kind => "it is not of the kind the setting needs",
        Ok(Some(certificate)) if !may_reference(&certificate) => "it is outside the surface's tenant",
        Ok(Some(certificate)) => return Ok(certificate),
        Ok(None) => "it does not exist",
        Err(_) => "the certificate store could not be read",
    };
    warn!(
        surface = %surface.surface_id,
        certificate_id = id,
        "Response authentication by mTLS cannot use a certificate: {why}"
    );
    Err(ResponseAuthFailure::Unverifiable)
}

fn unreadable(certificate: &Certificate) -> ResponseAuthFailure {
    warn!(certificate_id = %certificate.id, "Response authentication by mTLS cannot read a certificate");
    ResponseAuthFailure::Unverifiable
}

/// Every certificate in `certificate`'s PEM, leaf first.
fn chain(certificate: &Certificate) -> Result<Vec<CertificateDer<'static>>, ResponseAuthFailure> {
    let chain = rustls_pemfile::certs(
        &mut certificate
            .certificate_pem
            .as_bytes(),
    )
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| unreadable(certificate))?;
    if chain.is_empty() {
        return Err(unreadable(certificate));
    }
    Ok(chain)
}

fn leaf(certificate: &Certificate) -> Result<CertificateDer<'static>, ResponseAuthFailure> {
    chain(certificate)?
        .into_iter()
        .next()
        .ok_or_else(|| unreadable(certificate))
}

fn private_key(certificate: &Certificate) -> Result<PrivateKeyDer<'static>, ResponseAuthFailure> {
    let pem = certificate
        .private_key_pem
        .as_deref()
        .unwrap_or_default();
    rustls_pemfile::private_key(&mut pem.as_bytes())
        .ok()
        .flatten()
        .ok_or_else(|| unreadable(certificate))
}

/// Accepts a server certificate only when its SHA-256 fingerprint is a pinned one.
#[derive(Debug)]
struct PinnedServerVerifier {
    fingerprints: Vec<[u8; 32]>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if self
            .fingerprints
            .contains(&presented)
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self
                .provider
                .signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self
                .provider
                .signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::certificates::{CreateCertificateRequest, FilesystemCertificateStore, UpdateCertificateRequest};
    use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
    use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A certificate and its key, as PEM and DER.
    struct Issued {
        pem: String,
        key_pem: String,
        der: CertificateDer<'static>,
        key_der: Vec<u8>,
    }

    fn issued(
        certificate: rcgen::Certificate,
        key: &KeyPair,
    ) -> Issued {
        Issued {
            pem: certificate.pem(),
            key_pem: key.serialize_pem(),
            der: certificate.der().clone(),
            key_der: key.serialize_der(),
        }
    }

    fn leaf_params(names: &[&str]) -> CertificateParams {
        let mut params = CertificateParams::new(
            names
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
        )
        .expect("leaf params");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
        params
    }

    fn self_signed(names: &[&str]) -> Issued {
        let key = KeyPair::generate().expect("key");
        let certificate = leaf_params(names)
            .self_signed(&key)
            .expect("self-signed");
        issued(certificate, &key)
    }

    /// A CA, and a server certificate for `names` it issued.
    fn ca_and_leaf(names: &[&str]) -> (Issued, Issued) {
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = issued(
            ca_params
                .clone()
                .self_signed(&ca_key)
                .expect("ca"),
            &ca_key,
        );
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let key = KeyPair::generate().expect("leaf key");
        let leaf = leaf_params(names)
            .signed_by(&key, &issuer)
            .expect("leaf");
        (ca, issued(leaf, &key))
    }

    async fn store() -> (tempfile::TempDir, Arc<dyn CertificateStore>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = FilesystemCertificateStore::new(dir.path().to_path_buf())
            .await
            .expect("certificate store");
        (dir, Arc::new(store))
    }

    async fn put(
        store: &Arc<dyn CertificateStore>,
        id: &str,
        kind: CertificateKind,
        certificate: &Issued,
        with_key: bool,
        tenant_id: Option<&str>,
    ) {
        store
            .create_with_ids(
                CreateCertificateRequest {
                    tenant_id: tenant_id.map(String::from),
                    name: id.to_string(),
                    description: None,
                    tags: None,
                    kind,
                    certificate_pem: certificate.pem.clone(),
                    private_key_pem: with_key.then(|| certificate.key_pem.clone()),
                    expires_at: None,
                    active: None,
                    identity_did: None,
                },
                id.to_string(),
                format!("{id}-uuid"),
            )
            .await
            .expect("certificate stored");
    }

    fn surface(
        tenant_id: Option<&str>,
        mtls: serde_json::Value,
    ) -> AgentSurface {
        serde_json::from_value(json!({
            "surface_id": "surface-1", "name": "surface-1", "tenant_id": tenant_id,
            "access_point": {"listen_address": "0.0.0.0:9000", "route": "/agent", "protocol": "a2a"},
            "target": {"endpoint": "https://127.0.0.1", "response_auth": {"mtls": mtls}}
        }))
        .expect("surface parses")
    }

    fn pinned(ids: &[&str]) -> serde_json::Value {
        json!({"server_trust": {"type": "pinned", "certificate_ids": ids}})
    }

    fn ca(ids: &[&str]) -> serde_json::Value {
        json!({"server_trust": {"type": "ca", "ca_certificate_ids": ids}})
    }

    /// Accepts any client certificate, or none, so a test server can record what it was sent.
    #[derive(Debug)]
    struct AnyClientCertificate(Arc<CryptoProvider>);

    impl ClientCertVerifier for AnyClientCertificate {
        fn client_auth_mandatory(&self) -> bool {
            false
        }

        fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
            &[]
        }

        fn verify_client_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> Result<ClientCertVerified, rustls::Error> {
            Ok(ClientCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self
                    .0
                    .signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self
                    .0
                    .signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// A TLS server on 127.0.0.1 holding `certificate`, answering `200 ok` to every request
    /// and recording the client certificate of each handshake.
    struct TlsServer {
        port: u16,
        client_certificates: Arc<std::sync::Mutex<Vec<Option<Vec<u8>>>>>,
    }

    async fn serve(certificate: &Issued) -> TlsServer {
        serve_answering(certificate, "ok").await
    }

    /// [`serve`] answering `body` instead of `ok`.
    async fn serve_answering(
        certificate: &Issued,
        body: &'static str,
    ) -> TlsServer {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_client_cert_verifier(Arc::new(AnyClientCertificate(provider)))
            .with_single_cert(
                vec![certificate.der.clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.key_der.clone()).into(),
            )
            .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener
            .local_addr()
            .expect("address")
            .port();
        let client_certificates = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&client_certificates);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let presented = stream
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|chain| chain.first())
                        .map(|leaf| leaf.to_vec());
                    recorded
                        .lock()
                        .expect("lock")
                        .push(presented);
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 1024];
                    while !request
                        .windows(4)
                        .any(|window| window == b"\r\n\r\n")
                    {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => request.extend_from_slice(&buffer[..read]),
                        }
                    }
                    let answer =
                        format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                    let _ = stream
                        .write_all(answer.as_bytes())
                        .await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        TlsServer { port, client_certificates }
    }

    /// The `target.response_auth` that pins the certificate `bravo` of [`untrusted_target`].
    pub(crate) fn pinned_bravo() -> serde_json::Value {
        json!({"mtls": pinned(&["bravo"])})
    }

    /// A TLS server on 127.0.0.1 answering `200 ok`, whose certificate fails the trust of
    /// [`pinned_bravo`], and a certificate store holding the certificate `bravo` that trust pins.
    pub(crate) async fn untrusted_target() -> (u16, tempfile::TempDir, Arc<dyn CertificateStore>) {
        let (dir, store) = store().await;
        put(&store, "bravo", CertificateKind::ClientLeaf, &self_signed(&["127.0.0.1"]), false, None).await;
        let server = serve(&self_signed(&["127.0.0.1"])).await;
        (server.port, dir, store)
    }

    /// A TLS server on 127.0.0.1 answering `200` with `body`, holding the certificate `bravo`
    /// that [`pinned_bravo`] trusts, and a certificate store holding it.
    pub(crate) async fn trusted_target(body: &'static str) -> (u16, tempfile::TempDir, Arc<dyn CertificateStore>) {
        let (dir, store) = store().await;
        let bravo = self_signed(&["127.0.0.1"]);
        put(&store, "bravo", CertificateKind::ClientLeaf, &bravo, false, None).await;
        let server = serve_answering(&bravo, body).await;
        (server.port, dir, store)
    }

    async fn send(
        port: u16,
        tls: Option<&ClientConfig>,
    ) -> Result<String, reqwest::Error> {
        let url = format!("https://127.0.0.1:{port}/agent");
        let (client, _) = crate::egress::pinned_forward_client_with_tls(&url, std::time::Duration::from_secs(5), tls)
            .expect("the client builds");
        client
            .get(&url)
            .send()
            .await?
            .text()
            .await
    }

    async fn settings(
        cache: &TlsSettingsCache,
        surface: &AgentSurface,
        store: &Arc<dyn CertificateStore>,
    ) -> Arc<ClientConfig> {
        cache
            .settings(surface, Some(store))
            .await
            .expect("usable settings")
            .expect("an mTLS surface has settings")
            .config
    }

    #[tokio::test]
    async fn test_a_server_holding_the_pinned_certificate_is_served() {
        let (_dir, store) = store().await;
        let bravo = self_signed(&["bravo.example"]);
        put(&store, "bravo", CertificateKind::ClientLeaf, &bravo, false, None).await;
        let server = serve(&bravo).await;
        let tls = settings(&TlsSettingsCache::default(), &surface(None, pinned(&["bravo"])), &store).await;

        assert_eq!(
            send(server.port, Some(&tls))
                .await
                .expect("served"),
            "ok"
        );
    }

    #[tokio::test]
    async fn test_a_server_holding_another_certificate_fails_the_pinned_trust() {
        let (_dir, store) = store().await;
        put(&store, "bravo", CertificateKind::ClientLeaf, &self_signed(&["127.0.0.1"]), false, None).await;
        let server = serve(&self_signed(&["127.0.0.1"])).await;
        let surface = surface(None, pinned(&["bravo"]));
        let tls = settings(&TlsSettingsCache::default(), &surface, &store).await;

        let error = send(server.port, Some(&tls))
            .await
            .expect_err("refused in the handshake");
        assert_eq!(handshake_failure(&surface, &error), Some(ResponseAuthFailure::ServerUntrusted));
    }

    #[tokio::test]
    async fn test_a_server_certificate_chaining_to_the_configured_ca_for_the_target_host_is_served() {
        let (_dir, store) = store().await;
        let (bravo_ca, bravo) = ca_and_leaf(&["127.0.0.1"]);
        put(&store, "bravo-ca", CertificateKind::Ca, &bravo_ca, false, None).await;
        let server = serve(&bravo).await;
        let tls = settings(&TlsSettingsCache::default(), &surface(None, ca(&["bravo-ca"])), &store).await;

        assert_eq!(
            send(server.port, Some(&tls))
                .await
                .expect("served"),
            "ok"
        );
    }

    #[tokio::test]
    async fn test_a_ca_trust_refuses_a_certificate_for_another_host_or_from_another_ca() {
        let (_dir, store) = store().await;
        let (bravo_ca, other_host) = ca_and_leaf(&["bravo.example"]);
        put(&store, "bravo-ca", CertificateKind::Ca, &bravo_ca, false, None).await;
        let (_, other_ca) = ca_and_leaf(&["127.0.0.1"]);
        let surface = surface(None, ca(&["bravo-ca"]));
        let tls = settings(&TlsSettingsCache::default(), &surface, &store).await;

        for (case, certificate) in [
            ("a certificate for another host", &other_host),
            ("a certificate from another CA", &other_ca),
            ("a self-signed certificate", &self_signed(&["127.0.0.1"])),
        ] {
            let server = serve(certificate).await;
            let error = send(server.port, Some(&tls))
                .await
                .expect_err(case);
            assert_eq!(handshake_failure(&surface, &error), Some(ResponseAuthFailure::ServerUntrusted), "{case}");
        }
    }

    #[tokio::test]
    async fn test_the_gateway_presents_its_client_certificate_only_when_one_is_set() {
        let (_dir, store) = store().await;
        let bravo = self_signed(&["127.0.0.1"]);
        let gateway = self_signed(&["gateway.example"]);
        put(&store, "bravo", CertificateKind::ClientLeaf, &bravo, false, None).await;
        put(&store, "gateway", CertificateKind::ClientLeaf, &gateway, true, None).await;
        let server = serve(&bravo).await;
        let mut presenting = pinned(&["bravo"]);
        presenting["client_certificate_id"] = json!("gateway");

        let with_client = settings(&TlsSettingsCache::default(), &surface(None, presenting), &store).await;
        assert_eq!(
            send(server.port, Some(&with_client))
                .await
                .expect("served"),
            "ok"
        );
        let without_client = settings(&TlsSettingsCache::default(), &surface(None, pinned(&["bravo"])), &store).await;
        assert_eq!(
            send(server.port, Some(&without_client))
                .await
                .expect("served"),
            "ok"
        );

        assert_eq!(
            *server
                .client_certificates
                .lock()
                .expect("lock"),
            vec![Some(gateway.der.to_vec()), None]
        );
    }

    #[tokio::test]
    async fn test_the_settings_are_kept_until_a_certificate_they_use_changes() {
        let (_dir, store) = store().await;
        let first = self_signed(&["127.0.0.1"]);
        let renewed = self_signed(&["127.0.0.1"]);
        put(&store, "bravo", CertificateKind::ClientLeaf, &first, false, None).await;
        let cache = TlsSettingsCache::default();
        let surface = surface(None, pinned(&["bravo"]));

        let built = settings(&cache, &surface, &store).await;
        assert!(Arc::ptr_eq(&built, &settings(&cache, &surface, &store).await), "kept while unchanged");

        store
            .update(
                "bravo",
                UpdateCertificateRequest {
                    name: None,
                    description: None,
                    tags: None,
                    kind: None,
                    certificate_pem: Some(renewed.pem.clone()),
                    private_key_pem: None,
                    expires_at: None,
                    active: None,
                    identity_did: None,
                },
            )
            .await
            .expect("certificate renewed");
        let rebuilt = settings(&cache, &surface, &store).await;

        assert!(!Arc::ptr_eq(&built, &rebuilt), "built again after the change");
        assert_eq!(
            send(serve(&renewed).await.port, Some(&rebuilt))
                .await
                .expect("served"),
            "ok"
        );
        assert!(
            send(serve(&first).await.port, Some(&rebuilt))
                .await
                .is_err(),
            "the old certificate is no longer trusted"
        );
    }

    #[tokio::test]
    async fn test_each_setting_of_a_surface_keeps_its_own_settings_and_stamp() {
        let (_dir, store) = store().await;
        put(&store, "bravo", CertificateKind::ClientLeaf, &self_signed(&["127.0.0.1"]), false, None).await;
        put(&store, "bravo-ca", CertificateKind::Ca, &ca_and_leaf(&["127.0.0.1"]).0, false, None).await;
        let cache = TlsSettingsCache::default();
        let pinned_variant = surface(None, pinned(&["bravo"]));
        let ca_variant = surface(None, ca(&["bravo-ca"]));
        assert_eq!(cache.stamp(&pinned_variant), None, "nothing built yet");

        let first_pinned = settings(&cache, &pinned_variant, &store).await;
        let first_ca = settings(&cache, &ca_variant, &store).await;
        let pinned_stamp = cache.stamp(&pinned_variant);
        let ca_stamp = cache.stamp(&ca_variant);

        assert_eq!(cache.built.len(), 2);
        assert!(Arc::ptr_eq(&first_pinned, &settings(&cache, &pinned_variant, &store).await), "pinned kept");
        assert!(Arc::ptr_eq(&first_ca, &settings(&cache, &ca_variant, &store).await), "CA kept");
        assert!(pinned_stamp.is_some() && ca_stamp.is_some());
        assert_ne!(pinned_stamp, ca_stamp);
        assert_eq!(cache.stamp(&pinned_variant), pinned_stamp, "alternating keeps each stamp");
    }

    #[tokio::test]
    async fn test_forgetting_a_surface_drops_only_its_settings() {
        let (_dir, store) = store().await;
        put(&store, "bravo", CertificateKind::ClientLeaf, &self_signed(&["127.0.0.1"]), false, None).await;
        put(&store, "bravo-ca", CertificateKind::Ca, &ca_and_leaf(&["127.0.0.1"]).0, false, None).await;
        let cache = TlsSettingsCache::default();
        let mut other = surface(None, pinned(&["bravo"]));
        other.surface_id = "surface-2".to_string();
        settings(&cache, &surface(None, pinned(&["bravo"])), &store).await;
        settings(&cache, &surface(None, ca(&["bravo-ca"])), &store).await;
        let kept = settings(&cache, &other, &store).await;

        cache.forget("surface-1");

        assert_eq!(
            cache
                .built
                .iter()
                .map(|entry| entry.key().0.clone())
                .collect::<Vec<_>>(),
            vec!["surface-2".to_string()]
        );
        assert_eq!(cache.stamp(&surface(None, pinned(&["bravo"]))), None);
        assert!(Arc::ptr_eq(&kept, &settings(&cache, &other, &store).await), "another surface's settings kept");
    }

    #[tokio::test]
    async fn test_forgetting_all_drops_every_surfaces_settings() {
        let (_dir, store) = store().await;
        put(&store, "bravo", CertificateKind::ClientLeaf, &self_signed(&["127.0.0.1"]), false, None).await;
        let cache = TlsSettingsCache::default();
        let first = surface(None, pinned(&["bravo"]));
        let mut second = surface(None, pinned(&["bravo"]));
        second.surface_id = "surface-2".to_string();
        let built = settings(&cache, &first, &store).await;
        settings(&cache, &second, &store).await;
        assert_eq!(cache.built.len(), 2);

        cache.forget_all();

        assert_eq!(cache.built.len(), 0);
        assert_eq!(cache.stamp(&first), None);
        assert_eq!(cache.stamp(&second), None);
        assert!(!Arc::ptr_eq(&built, &settings(&cache, &first, &store).await), "built again after forgetting");
    }

    #[tokio::test]
    async fn test_a_renewed_certificate_opens_a_new_legacy_sse_session() {
        let (_dir, store) = store().await;
        put(&store, "bravo", CertificateKind::ClientLeaf, &self_signed(&["127.0.0.1"]), false, None).await;
        let mut surface = surface(None, pinned(&["bravo"]));
        surface.surface_id = "legacy-sse-renewal".to_string();
        let base = "https://127.0.0.1:9443";
        let built = || async {
            target_tls(&surface, Some(&store))
                .await
                .expect("usable settings")
                .expect("an mTLS surface has settings")
        };
        let key = |tls: TargetTls| {
            crate::mcp::sse_transport::session_key(
                base,
                Some(crate::mcp::sse_transport::ResponseCheck {
                    surface: &surface,
                    secrets: None,
                    stamp: Some(tls.stamp),
                }),
            )
        };

        let before = key(built().await);
        assert_eq!(key(built().await), before, "the same session while unchanged");

        store
            .update(
                "bravo",
                UpdateCertificateRequest {
                    name: None,
                    description: None,
                    tags: None,
                    kind: None,
                    certificate_pem: Some(self_signed(&["127.0.0.1"]).pem),
                    private_key_pem: None,
                    expires_at: None,
                    active: None,
                    identity_did: None,
                },
            )
            .await
            .expect("certificate renewed");

        assert_ne!(key(built().await), before, "a new session after the renewal");
    }

    #[tokio::test]
    async fn test_a_certificate_the_surface_cannot_use_makes_the_settings_unverifiable() {
        let certificate = self_signed(&["127.0.0.1"]);
        let mut client = pinned(&["bravo"]);
        client["client_certificate_id"] = json!("gateway");
        let mut crl = ca(&["bravo"]);
        crl["server_trust"]["check_crl"] = json!(true);
        for (case, surface, stored) in [
            ("a missing certificate", surface(None, pinned(&["other"])), vec![]),
            ("no pinned certificate", surface(None, pinned(&[])), vec![]),
            (
                "a CA pinned as a leaf",
                surface(None, pinned(&["bravo"])),
                vec![("bravo", CertificateKind::Ca, false, None)],
            ),
            (
                "a leaf used as a CA",
                surface(None, ca(&["bravo"])),
                vec![("bravo", CertificateKind::ClientLeaf, false, None)],
            ),
            (
                "another tenant's certificate",
                surface(Some("tenant-a"), pinned(&["bravo"])),
                vec![("bravo", CertificateKind::ClientLeaf, false, Some("tenant-b"))],
            ),
            (
                "a client certificate without its key",
                surface(None, client),
                vec![
                    ("bravo", CertificateKind::ClientLeaf, false, None),
                    ("gateway", CertificateKind::ClientLeaf, false, None),
                ],
            ),
            ("a CRL check", surface(None, crl), vec![("bravo", CertificateKind::Ca, false, None)]),
        ] {
            let (_dir, store) = store().await;
            for (id, kind, with_key, tenant_id) in stored {
                put(&store, id, kind, &certificate, with_key, tenant_id).await;
            }
            let outcome = TlsSettingsCache::default()
                .settings(&surface, Some(&store))
                .await;
            assert_eq!(outcome.err(), Some(ResponseAuthFailure::Unverifiable), "{case}");
        }
        assert_eq!(
            TlsSettingsCache::default()
                .settings(&surface(None, pinned(&["bravo"])), None)
                .await
                .err(),
            Some(ResponseAuthFailure::Unverifiable),
            "no certificate store"
        );
    }

    #[tokio::test]
    async fn test_a_tenant_surface_uses_its_own_or_an_appliance_wide_certificate() {
        for owner in [Some("tenant-a"), None] {
            let (_dir, store) = store().await;
            put(&store, "bravo", CertificateKind::ClientLeaf, &self_signed(&["127.0.0.1"]), false, owner).await;
            let outcome = TlsSettingsCache::default()
                .settings(&surface(Some("tenant-a"), pinned(&["bravo"])), Some(&store))
                .await;
            assert!(matches!(outcome, Ok(Some(_))), "{owner:?}");
        }
    }

    async fn tenant_client_certificate_outcome(
        mode: crate::config::credential_policy::RuleMode,
        client_owner: Option<&str>,
    ) -> Result<Option<TargetTls>, ResponseAuthFailure> {
        let (_dir, store) = store().await;
        put(&store, "bravo", CertificateKind::ClientLeaf, &self_signed(&["127.0.0.1"]), false, None).await;
        put(&store, "gateway", CertificateKind::ClientLeaf, &self_signed(&["gateway.example"]), true, client_owner)
            .await;
        let mut presenting = pinned(&["bravo"]);
        presenting["client_certificate_id"] = json!("gateway");
        let surface = surface(Some("tenant-a"), presenting);
        let policy: &'static crate::config::credential_policy::CredentialPolicyConfig =
            Box::leak(Box::new(crate::config::credential_policy::CredentialPolicyConfig {
                tenant_credential_isolation: mode,
                ..Default::default()
            }));
        crate::config::credential_policy::TEST_CREDENTIAL_POLICY
            .scope(policy, async {
                TlsSettingsCache::default()
                    .settings(&surface, Some(&store))
                    .await
            })
            .await
    }

    #[tokio::test]
    async fn test_an_appliance_wide_client_certificate_is_refused_to_a_tenant_surface_only_under_enforce() {
        use crate::config::credential_policy::RuleMode;
        assert!(matches!(tenant_client_certificate_outcome(RuleMode::Warn, None).await, Ok(Some(_))), "warn");
        assert_eq!(
            tenant_client_certificate_outcome(RuleMode::Enforce, None)
                .await
                .err(),
            Some(ResponseAuthFailure::Unverifiable),
            "enforce"
        );
        for mode in [RuleMode::Warn, RuleMode::Enforce] {
            assert!(
                matches!(tenant_client_certificate_outcome(mode, Some("tenant-a")).await, Ok(Some(_))),
                "the tenant's own client certificate under {mode:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_an_appliance_wide_server_trust_certificate_stays_usable_under_enforce() {
        let (_dir, store) = store().await;
        put(&store, "bravo", CertificateKind::ClientLeaf, &self_signed(&["127.0.0.1"]), false, None).await;
        let policy: &'static crate::config::credential_policy::CredentialPolicyConfig =
            Box::leak(Box::new(crate::config::credential_policy::CredentialPolicyConfig {
                tenant_credential_isolation: crate::config::credential_policy::RuleMode::Enforce,
                ..Default::default()
            }));
        let surface = surface(Some("tenant-a"), pinned(&["bravo"]));

        let outcome = crate::config::credential_policy::TEST_CREDENTIAL_POLICY
            .scope(policy, async {
                TlsSettingsCache::default()
                    .settings(&surface, Some(&store))
                    .await
            })
            .await;

        assert!(matches!(outcome, Ok(Some(_))));
    }

    #[tokio::test]
    async fn test_a_surface_without_mtls_has_no_settings_and_no_handshake_failure() {
        let (_dir, store) = store().await;
        let mut plain = surface(None, pinned(&["bravo"]));
        plain.target.response_auth = None;
        assert_eq!(
            TlsSettingsCache::default()
                .settings(&plain, Some(&store))
                .await
                .map(|tls| tls.is_some()),
            Ok(false)
        );

        let server = serve(&self_signed(&["127.0.0.1"])).await;
        let error = send(server.port, None)
            .await
            .expect_err("the default trust refuses a self-signed certificate");
        assert_eq!(handshake_failure(&plain, &error), None);
    }

    #[tokio::test]
    async fn test_a_target_that_cannot_be_reached_is_not_a_handshake_failure() {
        let (_dir, store) = store().await;
        put(&store, "bravo", CertificateKind::ClientLeaf, &self_signed(&["127.0.0.1"]), false, None).await;
        let surface = surface(None, pinned(&["bravo"]));
        let tls = settings(&TlsSettingsCache::default(), &surface, &store).await;
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind")
            .local_addr()
            .expect("address")
            .port();

        let error = send(closed, Some(&tls))
            .await
            .expect_err("nothing listens");
        assert!(error.is_connect(), "{error}");
        assert_eq!(handshake_failure(&surface, &error), None);
    }
}
