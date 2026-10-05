//! Direct-TLS handshake peer-cert capture.
//!
//! When the gateway terminates TLS itself, the rustls handshake exposes
//! any presented client certificate via `ServerConnection::peer_certificates()`.
//! This module provides:
//!
//! * [`PeerCertAcceptor`] — an `axum_server` `Accept` wrapper that, after
//!   each successful handshake, inserts an `Extension(DirectTlsPeerCert)`
//!   containing the leaf + chain DER bytes (or `None` when no cert was
//!   presented) into every request on that connection.
//! * [`promote_direct_peer_cert`] — a small tower middleware that, when a
//!   `DirectTlsPeerCert(Some(_))` is present on the request, promotes it
//!   into the canonical `PeerCertInfo` extension so that the auth
//!   middleware can consume it identically to the forwarded path.
//!
//! Two-step (capture → promote) keeps the acceptor `Service` type
//! statically uniform regardless of whether a cert was presented.

use std::io;
use std::sync::Arc;

use axum::extract::Request;
use axum::middleware::{AddExtension, Next};
use axum::response::Response;
use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsAcceptor;
use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower::Layer;

use crate::source_auth::models::{PeerCertInfo, PeerCertSource};

/// Connection-scoped extension carrying the peer-certificate captured at
/// TLS handshake time. `None` indicates the client did not present a cert
/// (only possible in `Optional` direct mode).
#[derive(Clone, Debug, Default)]
pub struct DirectTlsPeerCert(pub Option<PeerCertInfo>);

/// `axum_server::Accept` impl that wraps [`RustlsAcceptor`] and, after the
/// handshake, snapshots the presented client certificate into a
/// `DirectTlsPeerCert` extension on every request served over that
/// connection.
#[derive(Clone)]
pub struct PeerCertAcceptor {
    inner: RustlsAcceptor,
}

impl PeerCertAcceptor {
    pub fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl<I, S> Accept<I, S> for PeerCertAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = AddExtension<S, DirectTlsPeerCert>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(
        &self,
        stream: I,
        service: S,
    ) -> Self::Future {
        let acceptor = self.inner.clone();
        Box::pin(async move {
            let (stream, service) = acceptor
                .accept(stream, service)
                .await?;
            let server_conn = stream.get_ref().1;
            let peer = server_conn
                .peer_certificates()
                .and_then(|certs| build_peer_cert_info(certs));
            let ext = DirectTlsPeerCert(peer);
            let service = axum::Extension(ext).layer(service);
            Ok((stream, service))
        })
    }
}

fn build_peer_cert_info(chain: &[rustls_pki_types::CertificateDer<'_>]) -> Option<PeerCertInfo> {
    let leaf = chain.first()?;
    let leaf_der = leaf.as_ref().to_vec();
    let chain_der: Vec<Vec<u8>> = chain
        .iter()
        .skip(1)
        .map(|c| c.as_ref().to_vec())
        .collect();
    Some(PeerCertInfo {
        leaf_der,
        chain_der,
        source: PeerCertSource::DirectTls,
    })
}

/// Promotion middleware: if a `DirectTlsPeerCert(Some(_))` extension is
/// present on the request (set by [`PeerCertAcceptor`]) and no
/// `PeerCertInfo` is present yet, insert the inner [`PeerCertInfo`] into
/// the request extensions so downstream auth treats it identically to
/// forwarded certs.
///
/// Forwarded-cert wins on conflict (forwarded layer runs later in the
/// stack and would not overwrite — but a direct handshake cert should be
/// preferred when both exist; we therefore explicitly favour the direct
/// cert by inserting unconditionally when present).
pub async fn promote_direct_peer_cert(
    mut req: Request,
    next: Next,
) -> Response {
    let direct = req
        .extensions()
        .get::<DirectTlsPeerCert>()
        .cloned();
    if let Some(DirectTlsPeerCert(Some(peer))) = direct {
        req.extensions_mut()
            .insert(peer);
    }
    next.run(req).await
}

/// Load the inbound client-auth material from the certificate store.
///
/// Returns `Ok(None)` when direct client auth is disabled or when no CA
/// certs (kind = [`crate::certificates::CertificateKind::Ca`], active) exist
/// in the store. Returns `Ok(Some(...))` ready to feed
/// [`crate::server::load_server_config`].
pub async fn load_inbound_client_auth(
    cert_store: Option<&Arc<dyn crate::certificates::store::CertificateStore>>,
    cfg: &crate::config::types::ClientAuthConfig,
) -> anyhow::Result<Option<crate::server::DirectClientAuth>> {
    use crate::config::types::DirectClientAuthMode;
    if cfg.direct == DirectClientAuthMode::Disabled {
        return Ok(None);
    }
    let Some(store) = cert_store else {
        anyhow::bail!("client_auth.direct = {:?} requires a certificate store", cfg.direct);
    };

    let items = store
        .list_all()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list certificates for client auth: {e}"))?;

    let mut ca_certs: Vec<rustls_pki_types::CertificateDer<'static>> = Vec::new();
    for item in items {
        if !item.active || item.kind != crate::certificates::CertificateKind::Ca {
            continue;
        }
        let cert = store
            .get(&item.id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to load CA cert {}: {e}", item.id))?;
        let Some(cert) = cert else {
            continue;
        };
        let (_, parsed) = x509_parser::pem::parse_x509_pem(
            cert.certificate_pem
                .as_bytes(),
        )
        .map_err(|e| anyhow::anyhow!("Invalid PEM in CA cert {}: {e}", item.id))?;
        if parsed.label != "CERTIFICATE" {
            anyhow::bail!("CA cert {} has wrong PEM tag '{}'", item.id, parsed.label);
        }
        ca_certs.push(rustls_pki_types::CertificateDer::from(parsed.contents));
    }

    if ca_certs.is_empty() {
        anyhow::bail!("client_auth.direct = {:?} but no active CA certificates (kind=Ca) found in store", cfg.direct);
    }

    Ok(Some(crate::server::DirectClientAuth { mode: cfg.direct, ca_certs }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::StatusCode;
    use axum::middleware::from_fn;
    use axum::routing::get;
    use tower::ServiceExt;

    async fn introspect(req: Request) -> String {
        match req
            .extensions()
            .get::<PeerCertInfo>()
        {
            Some(p) => format!("yes:{:?}:{}", p.source, p.leaf_der.len()),
            None => "no".to_string(),
        }
    }

    async fn run(direct: Option<DirectTlsPeerCert>) -> String {
        let app: Router = Router::new()
            .route("/", get(introspect))
            .layer(from_fn(promote_direct_peer_cert));

        let mut req: Request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();
        if let Some(d) = direct {
            req.extensions_mut().insert(d);
        }

        let resp = app
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn promotion_noop_when_extension_absent() {
        assert_eq!(run(None).await, "no");
    }

    #[tokio::test]
    async fn promotion_noop_when_inner_none() {
        assert_eq!(run(Some(DirectTlsPeerCert(None))).await, "no");
    }

    #[tokio::test]
    async fn promotion_inserts_peer_cert_info_when_present() {
        let peer = PeerCertInfo {
            leaf_der: vec![1, 2, 3, 4],
            chain_der: vec![],
            source: PeerCertSource::DirectTls,
        };
        let out = run(Some(DirectTlsPeerCert(Some(peer)))).await;
        assert_eq!(out, "yes:DirectTls:4");
    }

    #[test]
    fn build_peer_cert_info_handles_empty_chain() {
        let chain: Vec<rustls_pki_types::CertificateDer<'static>> = vec![];
        assert!(build_peer_cert_info(&chain).is_none());
    }

    #[test]
    fn build_peer_cert_info_separates_leaf_from_chain() {
        let leaf = rustls_pki_types::CertificateDer::from(vec![0xAAu8; 16]);
        let intermediate = rustls_pki_types::CertificateDer::from(vec![0xBBu8; 8]);
        let root = rustls_pki_types::CertificateDer::from(vec![0xCCu8; 4]);
        let chain = vec![leaf.clone(), intermediate.clone(), root.clone()];
        let info = build_peer_cert_info(&chain).unwrap();
        assert_eq!(info.leaf_der.len(), 16);
        assert_eq!(info.chain_der.len(), 2);
        assert_eq!(info.chain_der[0].len(), 8);
        assert_eq!(info.chain_der[1].len(), 4);
        assert_eq!(info.source, PeerCertSource::DirectTls);
    }
}
