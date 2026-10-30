use std::sync::Arc;

use crate::comm::didcomm::client::DIDCommClient;
use crate::gateways::connection_points::types::ConnectionPointType;
use crate::gateways::connection_points::ws_listener::ListenerInfo;
use crate::gateways::connection_points::{FileSystemConnectionPointStore, MessageStore};
use crate::gateways::did_cache::DIDCacheConfig;
use crate::gateways::types::Gateway;
use crate::gateways::{ConnectionPointListenerManager, FileSystemGatewayStore, GatewayStore};

/// Re-runs the calling test alone in a child process, where the receiver's
/// process-wide stores start empty, and asserts that it passed. Returns `true`
/// in the parent, which then returns; `false` in the child, which runs the body.
pub(crate) fn rerun_in_isolated_process() -> bool {
    if std::env::var_os("AG_RECEIVE_TEST_CHILD").is_some() {
        return false;
    }
    let test_name = std::thread::current()
        .name()
        .expect("test thread name")
        .to_string();
    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", &test_name, "--nocapture"])
        .env("AG_RECEIVE_TEST_CHILD", "1")
        .output()
        .expect("run receiver regression with isolated globals");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed"),
        "isolated receiver regression did not run and pass exactly one test:\n{}\n{}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

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
