use std::sync::Arc;

use crate::comm::didcomm::client::DIDCommClient;
use crate::gateways::connection_points::types::ConnectionPointType;
use crate::gateways::connection_points::ws_listener::ListenerInfo;
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

    let (manager, issuer_dir) = test_listener_manager(root).await;
    crate::gateways::init_listener_manager(Arc::new(manager.with_gateway_store(gateway_store))).await;
    issuer_dir
}

/// A listener manager over empty stores under `root`, with no listeners and no
/// gateway store. Returns the VC issuer's temp dir, which the caller keeps
/// alive for the test's duration.
pub(crate) async fn test_listener_manager(
    root: &std::path::Path
) -> (ConnectionPointListenerManager, tempfile::TempDir) {
    let (vc_issuer, issuer_dir) = crate::identity::test_helpers::test_vc_issuer().await;
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
    .unwrap();
    (manager, issuer_dir)
}

/// A registered-listener record for Connection Point `cp-1` whose DIDComm
/// client has no mediator, so it is built without any network access.
pub(crate) async fn test_listener(instance_id: &str) -> ListenerInfo {
    let connection_point_did = "did:example:connection-point".to_string();
    ListenerInfo {
        id: "cp-1".to_string(),
        instance_id: instance_id.to_string(),
        gateway_id: "gw-1".to_string(),
        connection_point_id: "cp-1".to_string(),
        gateway_did: connection_point_did.clone(),
        mediator_did: "did:example:mediator".to_string(),
        name: "Connection Point".to_string(),
        cp_type: ConnectionPointType::OobAcceptor,
        abort_handle: tokio::spawn(async {}).abort_handle(),
        metrics: Default::default(),
        client: DIDCommClient::new(connection_point_did, Vec::new(), None, None)
            .await
            .unwrap(),
    }
}
