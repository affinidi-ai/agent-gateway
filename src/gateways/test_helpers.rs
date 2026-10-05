use std::sync::Arc;

use crate::gateways::connection_points::{FileSystemConnectionPointStore, MessageStore};
use crate::gateways::did_cache::DIDCacheConfig;
use crate::gateways::types::Gateway;
use crate::gateways::{ConnectionPointListenerManager, FileSystemGatewayStore, GatewayStore};

/// The fabric-receive path only attributes requests to paired peers whose
/// issuers are known, so install a listener manager whose gateway store holds
/// `peers`. Returns the VC issuer's temp dir, which the caller keeps alive for
/// the test's duration.
pub(crate) async fn install_listener_manager_with_peers(
    root: &std::path::Path,
    peers: &[Gateway],
) -> tempfile::TempDir {
    let (vc_issuer, issuer_dir) = crate::identity::test_helpers::test_vc_issuer().await;
    let gateway_store = Arc::new(
        FileSystemGatewayStore::new(root.join("gateways"), Some("did:web:receiver-gateway.example".to_string()))
            .await
            .unwrap(),
    );
    for peer in peers {
        gateway_store
            .create(peer)
            .await
            .unwrap();
    }

    let manager = ConnectionPointListenerManager::new(
        Arc::new(vc_issuer),
        Arc::new(
            MessageStore::new(root.join("messages"))
                .await
                .unwrap(),
        ),
        Arc::new(
            FileSystemConnectionPointStore::new(root.join("connection_points"))
                .await
                .unwrap(),
        ),
        DIDCacheConfig {
            storage_path: root
                .join("did_cache")
                .to_string_lossy()
                .into_owned(),
            ..DIDCacheConfig::default()
        },
    )
    .await
    .unwrap()
    .with_gateway_store(gateway_store);
    crate::gateways::init_listener_manager(Arc::new(manager)).await;
    issuer_dir
}
