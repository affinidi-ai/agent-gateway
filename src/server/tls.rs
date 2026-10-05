use anyhow::{Context, Result};
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use rustls_pki_types::CertificateDer;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use crate::config::types::DirectClientAuthMode;

/// Optional client-certificate (mTLS) configuration for the inbound
/// listener. When `Some`, the TLS handshake will request a client
/// certificate; when [`DirectClientAuthMode::Required`], handshakes
/// without a presented cert fail at the TLS layer.
///
/// Per-channel `MtlsAuthConfig` still decides whether a given channel
/// requires the cert and how to bind it to an identity.
#[derive(Clone)]
pub struct DirectClientAuth {
    pub mode: DirectClientAuthMode,
    /// Trusted CA roots used to validate client cert chains.
    pub ca_certs: Vec<CertificateDer<'static>>,
}

/// Load TLS certificates and private key from PEM files
pub fn load_tls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<ServerConfig>> {
    load_server_config(cert_path, key_path, None)
}

/// Load server config (public for axum_proxy).
///
/// When `client_auth` is `Some` and the mode is not `Disabled`, the
/// resulting `ServerConfig` will request (Optional) or require (Required)
/// a client certificate during the TLS handshake, validated against the
/// supplied CA roots via `WebPkiClientVerifier`.
pub fn load_server_config(
    cert_path: &Path,
    key_path: &Path,
    client_auth: Option<DirectClientAuth>,
) -> Result<Arc<ServerConfig>> {
    // Load certificate chain
    let cert_file =
        File::open(cert_path).with_context(|| format!("Failed to open certificate file: {:?}", cert_path))?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<_> = certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .context("Failed to parse certificate chain")?;

    if cert_chain.is_empty() {
        anyhow::bail!("No certificates found in {:?}", cert_path);
    }

    // Load private key
    let key_file = File::open(key_path).with_context(|| format!("Failed to open private key file: {:?}", key_path))?;
    let mut key_reader = BufReader::new(key_file);
    let key = private_key(&mut key_reader)
        .context("Failed to parse private key")?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {:?}", key_path))?;

    let builder = ServerConfig::builder();
    let config = match client_auth {
        None
        | Some(DirectClientAuth {
            mode: DirectClientAuthMode::Disabled,
            ..
        }) => builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .context("Failed to build TLS configuration")?,
        Some(DirectClientAuth { mode, ca_certs }) => {
            if ca_certs.is_empty() {
                anyhow::bail!(
                    "client_auth.direct = {:?} requires at least one CA certificate (kind=Ca) in the certificate store",
                    mode
                );
            }
            let mut roots = rustls::RootCertStore::empty();
            for der in &ca_certs {
                roots
                    .add(der.clone())
                    .context("Failed to add client CA certificate to root store")?;
            }
            let verifier_builder = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots));
            let verifier = match mode {
                DirectClientAuthMode::Optional => verifier_builder
                    .allow_unauthenticated()
                    .build()
                    .context("Failed to build optional client cert verifier")?,
                DirectClientAuthMode::Required => verifier_builder
                    .build()
                    .context("Failed to build required client cert verifier")?,
                DirectClientAuthMode::Disabled => unreachable!(),
            };
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(cert_chain, key)
                .context("Failed to build TLS configuration with client auth")?
        }
    };

    Ok(Arc::new(config))
}

/// Create a TLS client configuration for upstream connections
#[allow(dead_code)]
pub fn create_client_tls_config(verify: bool) -> Result<Arc<rustls::ClientConfig>> {
    let mut root_store = rustls::RootCertStore::empty();

    if verify {
        // Load system root certificates
        let certs = rustls_native_certs::load_native_certs();
        for cert in certs.certs {
            root_store.add(cert).ok();
        }
    } else {
        // Disable certificate verification (not recommended for production)
        tracing::warn!("TLS certificate verification is disabled for upstream connections");
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}
