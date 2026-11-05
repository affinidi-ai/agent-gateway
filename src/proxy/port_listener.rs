//! Port listeners that stay bound while the routes they serve change.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, PoisonError, RwLock};

use axum::Router;
use axum::extract::Request;
use axum::response::Response;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use rustls::ServerConfig;
use tokio::task::AbortHandle;
use tower::ServiceExt;
use tracing::error;

use crate::config::GatewayConfig;
use crate::server::DirectClientAuth;

/// The router a bound listener serves. Each request runs on the router current
/// when it arrives, so a swap takes effect on the next request of every
/// connection, including one kept alive across the swap.
#[derive(Clone)]
pub struct SwappableRouter(Arc<RwLock<Router>>);

impl SwappableRouter {
    pub fn new(router: Router) -> Self {
        Self(Arc::new(RwLock::new(router)))
    }

    pub fn swap(
        &self,
        router: Router,
    ) {
        *self
            .0
            .write()
            .unwrap_or_else(PoisonError::into_inner) = router;
    }

    fn current(&self) -> Router {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The router to serve on a listener: it hands every request to the
    /// current router.
    pub fn entry(&self) -> Router {
        let routers = self.clone();
        Router::new().fallback(move |request: Request| {
            let router = routers.current();
            async move {
                let response: Result<Response, Infallible> = router.oneshot(request).await;
                response.unwrap_or_else(|never| match never {})
            }
        })
    }
}

/// What a port listener binds: its socket addresses and whether it speaks TLS.
/// A listener is bound again only when this changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortBinding {
    pub addresses: Vec<SocketAddr>,
    pub tls: bool,
}

/// A bound, serving port listener. Dropping it stops the listener.
pub struct BoundPort {
    binding: PortBinding,
    router: SwappableRouter,
    tls: Option<RustlsConfig>,
    handle: AbortHandle,
}

impl BoundPort {
    /// Bind `binding` and serve `router` on it. A TLS binding needs
    /// `tls_config`; `capture_peer_certs` passes direct-TLS client certificates
    /// on to each request.
    pub async fn bind(
        port: u16,
        binding: PortBinding,
        router: Router,
        tls_config: Option<Arc<ServerConfig>>,
        capture_peer_certs: bool,
    ) -> anyhow::Result<Self> {
        let tls = match (binding.tls, tls_config) {
            (true, Some(tls_config)) => Some(RustlsConfig::from_config(tls_config)),
            (true, None) => anyhow::bail!("Port {port} speaks TLS but has no TLS configuration"),
            (false, _) => None,
        };
        let listeners = super::server::bind_inbound_listeners(&binding.addresses).await?;
        let router = SwappableRouter::new(router);
        let app = router.entry();
        let serve_tls = tls.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = serve(listeners, app, serve_tls, capture_peer_certs).await {
                error!("Port listener error for port {port}: {e}");
            }
        })
        .abort_handle();
        Ok(Self { binding, router, tls, handle })
    }

    /// Whether this listener is still serving and bound as `binding` asks.
    pub fn serves(
        &self,
        binding: &PortBinding,
    ) -> bool {
        self.binding == *binding && !self.handle.is_finished()
    }

    /// Serve `router` from the next request on, and `tls_config`, when given,
    /// from the next TLS handshake on, without unbinding the port.
    pub fn swap(
        &self,
        router: Router,
        tls_config: Option<Arc<ServerConfig>>,
    ) {
        self.router.swap(router);
        if let (Some(tls), Some(tls_config)) = (&self.tls, tls_config) {
            tls.reload_from_config(tls_config);
        }
    }
}

impl Drop for BoundPort {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// The TLS configuration of a port listener, from the gateway certificate.
/// `None`, logged, when it cannot be loaded: a listener already bound keeps
/// the configuration it has, and a new one is not bound.
pub fn listener_tls_config(
    port: u16,
    config: &GatewayConfig,
    direct_client_auth: Option<&Arc<DirectClientAuth>>,
) -> Option<Arc<ServerConfig>> {
    crate::server::load_server_config(
        &config.tls.cert_path,
        &config.tls.key_path,
        direct_client_auth
            .map(|auth| auth.as_ref())
            .cloned(),
    )
    .inspect_err(|e| error!("Could not load the TLS configuration of port {port}: {e}"))
    .ok()
}

async fn serve(
    listeners: Vec<tokio::net::TcpListener>,
    app: Router,
    tls: Option<RustlsConfig>,
    capture_peer_certs: bool,
) -> anyhow::Result<()> {
    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    match tls {
        Some(tls) => {
            let acceptor = RustlsAcceptor::new(tls);
            let servers = listeners
                .into_iter()
                .map(axum_server::Server::<SocketAddr>::from_listener);
            if capture_peer_certs {
                futures::future::try_join_all(servers.map(|server| {
                    server
                        .acceptor(crate::source_auth::peer_cert::PeerCertAcceptor::new(acceptor.clone()))
                        .serve(make_service.clone())
                }))
                .await?;
            } else {
                futures::future::try_join_all(servers.map(|server| {
                    server
                        .acceptor(acceptor.clone())
                        .serve(make_service.clone())
                }))
                .await?;
            }
        }
        None => {
            futures::future::try_join_all(
                listeners
                    .into_iter()
                    .map(|listener| axum::serve(listener, make_service.clone()).into_future()),
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;

    fn router_answering(path: &'static str) -> Router {
        Router::new().route(path, get(move || async move { path }))
    }

    async fn status_of(
        router: &SwappableRouter,
        path: &str,
    ) -> axum::http::StatusCode {
        router
            .entry()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn a_swapped_router_serves_its_routes_and_drops_the_old_ones() {
        let router = SwappableRouter::new(router_answering("/old"));
        assert_eq!(status_of(&router, "/old").await, axum::http::StatusCode::OK);

        router.swap(router_answering("/new"));

        assert_eq!(status_of(&router, "/new").await, axum::http::StatusCode::OK);
        assert_eq!(status_of(&router, "/old").await, axum::http::StatusCode::NOT_FOUND);
    }

    fn loopback_binding() -> PortBinding {
        PortBinding {
            addresses: vec![SocketAddr::from(([127, 0, 0, 1], 0))],
            tls: false,
        }
    }

    #[tokio::test]
    async fn a_listener_serves_another_binding_only_when_it_is_the_same() {
        let bound = BoundPort::bind(0, loopback_binding(), router_answering("/"), None, false)
            .await
            .unwrap();

        assert!(bound.serves(&loopback_binding()));
        assert!(!bound.serves(&PortBinding {
            tls: true,
            ..loopback_binding()
        }));
        assert!(!bound.serves(&PortBinding {
            addresses: vec![SocketAddr::from(([127, 0, 0, 2], 0))],
            tls: false,
        }));
    }

    #[tokio::test]
    async fn a_tls_binding_without_a_tls_configuration_is_not_bound() {
        let error = BoundPort::bind(
            0,
            PortBinding {
                tls: true,
                ..loopback_binding()
            },
            router_answering("/"),
            None,
            false,
        )
        .await
        .err()
        .expect("a TLS binding needs a TLS configuration");

        assert_eq!(error.to_string(), "Port 0 speaks TLS but has no TLS configuration");
    }
}
