//! Keeps `/v1/gateways/*` and `/v1/payment-gateways/*` apart. Each route
//! family serves one [`GatewayRole`]: a gateway of the other role named by the
//! `{id}` or `{gateway_id}` path parameter is answered `404`, so `gateways.*` never reaches a
//! payment gateway and `payment_gateways.*` never reaches a peer. Handlers
//! read the family's role from [`GatewayRoleScope`] to list and create.

use std::sync::Arc;

use axum::{
    Extension,
    extract::{RawPathParams, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::MethodRouter,
};

use super::{store::GatewayStore, types::GatewayRole};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayRoleScope(pub GatewayRole);

/// The role a handler serves; a route outside any family serves peers.
pub fn scoped_role(scope: &Option<Extension<GatewayRoleScope>>) -> GatewayRole {
    scope
        .as_ref()
        .map(|Extension(GatewayRoleScope(role))| *role)
        .unwrap_or_default()
}

/// Limits `route` to gateways of `role`.
pub fn scope_route<S: GatewayStore + 'static>(
    route: MethodRouter,
    store: Arc<S>,
    role: GatewayRole,
) -> MethodRouter {
    route.layer(axum::middleware::from_fn_with_state((store, role), enforce::<S>))
}

async fn enforce<S: GatewayStore>(
    State((store, role)): State<(Arc<S>, GatewayRole)>,
    params: RawPathParams,
    mut request: Request,
    next: Next,
) -> Response {
    let id = params
        .iter()
        .find(|(name, _)| matches!(*name, "id" | "gateway_id"))
        .map(|(_, value)| value.to_string());
    if let Some(id) = id {
        match store.get(&id).await {
            Ok(Some(gateway)) if gateway.role != role => {
                return (StatusCode::NOT_FOUND, "Gateway not found").into_response();
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!(gateway_id = %id, "Failed to load gateway for role scope: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load gateway").into_response();
            }
        }
    }
    request
        .extensions_mut()
        .insert(GatewayRoleScope(role));
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::{
        FileSystemGatewayStore,
        types::{Gateway, GatewayType},
    };
    use axum::{Router, body::Body, routing::get};
    use tower::ServiceExt;

    async fn store_with(gateways: &[Gateway]) -> (Arc<FileSystemGatewayStore>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FileSystemGatewayStore::new(dir.path().to_path_buf(), None)
                .await
                .unwrap(),
        );
        for gateway in gateways {
            store
                .create(gateway)
                .await
                .unwrap();
        }
        (store, dir)
    }

    fn remote(
        id: &str,
        role: GatewayRole,
    ) -> Gateway {
        let mut gateway = Gateway::new(id.into(), String::new(), format!("did:web:{id}.example"), GatewayType::Remote);
        gateway.id = id.into();
        gateway.role = role;
        gateway
    }

    async fn echo_role(scope: Option<Extension<GatewayRoleScope>>) -> String {
        format!("{:?}", scoped_role(&scope))
    }

    async fn call(
        store: Arc<FileSystemGatewayStore>,
        role: GatewayRole,
        uri: &str,
    ) -> (StatusCode, String) {
        let app = Router::new()
            .route("/gw/{id}", scope_route(get(echo_role), store.clone(), role))
            .route("/gw", scope_route(get(echo_role), store, role));
        let response = app
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn a_gateway_of_the_route_role_reaches_the_handler_with_that_scope() {
        let (store, _dir) = store_with(&[remote("pay", GatewayRole::Payment)]).await;
        assert_eq!(call(store, GatewayRole::Payment, "/gw/pay").await, (StatusCode::OK, "Payment".to_string()));
    }

    #[tokio::test]
    async fn a_gateway_of_the_other_role_is_not_found() {
        let (store, _dir) = store_with(&[remote("pay", GatewayRole::Payment), remote("peer", GatewayRole::Peer)]).await;
        assert_eq!(
            call(store.clone(), GatewayRole::Peer, "/gw/pay")
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(store, GatewayRole::Payment, "/gw/peer")
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn an_unknown_id_and_a_route_without_id_pass_through_with_the_scope() {
        let (store, _dir) = store_with(&[]).await;
        assert_eq!(
            call(store.clone(), GatewayRole::Payment, "/gw/missing").await,
            (StatusCode::OK, "Payment".to_string())
        );
        assert_eq!(call(store, GatewayRole::Peer, "/gw").await, (StatusCode::OK, "Peer".to_string()));
    }

    #[test]
    fn a_handler_outside_any_family_serves_peers() {
        assert_eq!(scoped_role(&None), GatewayRole::Peer);
    }
}
