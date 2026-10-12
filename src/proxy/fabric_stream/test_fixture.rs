//! A receiving gateway's Fabric stream runtime with one surface and one paired
//! peer, for tests that admit Opens the way the peer's current sender builds
//! them.

use super::*;
use crate::gateways::connection_points::messages::MessageMetadata;

/// A receiving gateway with one surface and one paired peer, fed the
/// capability queries and Opens the peer's current sender builds: both
/// envelope times set, and an Open naming its capability offer.
pub(crate) struct OpenFixture {
    pub(crate) runtime: Arc<StreamRuntime>,
    pub(crate) listener: ListenerGeneration,
    pub(crate) connection: crate::gateways::connection_points::types::GatewayConnectionPoint,
    pub(crate) peer: crate::gateways::types::Gateway,
    pub(crate) surfaces_path: std::path::PathBuf,
    _directory: tempfile::TempDir,
    _paired_dir: tempfile::TempDir,
}

impl OpenFixture {
    pub(crate) const SURFACE_ID: &'static str = "surface";

    pub(crate) async fn new() -> Self {
        use crate::gateways::connection_points::types::{ConnectionPointType, GatewayConnectionPoint};
        use crate::gateways::types::{Gateway, GatewayType};
        use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};

        let directory = tempfile::tempdir().unwrap();
        let surfaces_path = directory
            .path()
            .join("surfaces");
        let store = FileSystemAgentSurfaceStore::new(surfaces_path.clone())
            .await
            .unwrap();
        // The stream lifetime is clamped to 1 s, far below the Open's
        // deadline, envelope expiry and offer lifetime.
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": Self::SURFACE_ID, "name": "Surface",
            "mcp_http": {"stream_idle_timeout_secs": 1, "stream_max_lifetime_secs": 1},
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://target.example/mcp"}
        }))
        .unwrap();
        store
            .save(&surface)
            .await
            .unwrap();
        let mut connection = GatewayConnectionPoint::new(
            "gateway".into(),
            "mediator".into(),
            "did:example:local".into(),
            "Connection".into(),
            String::new(),
            "oob".into(),
            String::new(),
            serde_json::json!({}),
            None,
            ConnectionPointType::User,
            String::new(),
        );
        connection.id = "cp".into();
        let mut peer = Gateway::new("Peer".into(), String::new(), "did:example:peer".into(), GatewayType::Remote);
        peer.exposure_mode = Some(crate::gateways::types::ExposureMode::All);
        let mut paired = peer.clone();
        paired.issuer_did = Some("did:example:peer-gateway".into());
        let paired_dir =
            crate::gateways::test_helpers::install_listener_manager_with_peers(directory.path(), &[paired]).await;
        let capabilities = StreamCapabilities::local(true, true);
        let runtime = Arc::new(StreamRuntime {
            registry: ReceiveRegistry::new(RegistryLimits {
                max_streams: 4,
                max_peer_streams: 4,
                max_surface_streams: 4,
                max_peer_listens: 4,
                max_surface_listens: 4,
            })
            .unwrap(),
            peers: PeerCapabilities::new(capabilities.clone()),
            local_capabilities: capabilities,
            listeners: Mutex::new(HashMap::new()),
        });
        let listener = runtime
            .listener(
                connection.id.clone(),
                connection
                    .connection_point_did
                    .clone(),
            )
            .unwrap();
        Self {
            runtime,
            listener,
            connection,
            peer,
            surfaces_path,
            _directory: directory,
            _paired_dir: paired_dir,
        }
    }

    pub(crate) fn envelope(
        &self,
        message_type: MessageType,
        id: Uuid,
        thid: Uuid,
        body: serde_json::Value,
    ) -> ReceivedMessage {
        let now = crate::gateways::connection_points::envelope_replay::now_secs();
        let mut message = ReceivedMessage::new(
            self.connection.id.clone(),
            self.peer.id.clone(),
            message_type.to_string(),
            id.to_string(),
            Some(thid.to_string()),
            Some(self.peer.did.clone()),
            vec![
                self.connection
                    .connection_point_did
                    .clone(),
            ],
            Some(now),
            Some(now + 60),
            body,
            MessageMetadata {
                authenticated: true,
                encrypted: true,
                from_key: None,
                extra: serde_json::Value::Null,
            },
        )
        .with_context("agent_surface_storage_path", serde_json::json!(self.surfaces_path));
        self.listener
            .stamp(&mut message);
        message
    }

    pub(crate) fn capability_query(
        &self,
        nonce: Uuid,
    ) -> ReceivedMessage {
        let query = CapabilityMessage {
            nonce,
            capabilities: StreamCapabilities::local(true, true),
        };
        self.envelope(MessageType::ForwardStreamQuery, nonce, nonce, serde_json::to_value(query).unwrap())
    }

    pub(crate) fn open(
        &self,
        capability_nonce: Uuid,
    ) -> ReceivedMessage {
        let stream_id = Uuid::new_v4();
        let request = wire::OpenRequest {
            capability_nonce,
            channel_id: Self::SURFACE_ID.into(),
            variant_alias: None,
            path: "/mcp".into(),
            headers: std::collections::BTreeMap::from([
                ("mcp-protocol-version".into(), vec![crate::mcp::MCP_MODERN_VERSION.into()]),
                ("mcp-method".into(), vec!["tools/list".into()]),
            ]),
            body_bytes: 0,
            response_window_bytes: wire::MAX_CHUNK_BYTES as u32,
            deadline_ms: u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap() + 60_000,
            trace_id: Uuid::new_v4(),
        };
        let frame = wire::StreamFrame {
            stream_id,
            payload: wire::FramePayload::Open { request },
        };
        self.envelope(MessageType::ForwardStreamFrame, Uuid::new_v4(), stream_id, serde_json::to_value(frame).unwrap())
    }

    /// Whether the offer for `nonce` is live at `at`. Asking about a later
    /// instant drops the offers that have expired by then.
    pub(crate) fn offered(
        &self,
        query: &ReceivedMessage,
        nonce: Uuid,
        at: Instant,
    ) -> bool {
        let binding = registry::StreamBinding {
            peer_did: self.peer.did.clone(),
            recipient_did: self
                .connection
                .connection_point_did
                .clone(),
            connection_point_id: self.connection.id.clone(),
            listener_instance_id: query.context[INSTANCE_CONTEXT]
                .as_str()
                .unwrap()
                .to_string(),
            surface_id: "capabilities".into(),
        };
        self.runtime
            .peers
            .offered(&binding, nonce, at)
            .is_some()
    }
}

/// Runs the calling test alone in a child process: the fixture installs the
/// process-wide listener manager. Returns false in the parent, which has
/// checked the child's outcome.
pub(crate) async fn in_isolated_child(what: &str) -> bool {
    if std::env::var_os("ATG_FABRIC_STREAM_ADMISSION_CHILD").is_some() {
        return true;
    }
    let test_name = std::thread::current()
        .name()
        .unwrap()
        .to_string();
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test_name, "--nocapture"])
        .env("ATG_FABRIC_STREAM_ADMISSION_CHILD", "1")
        .env("RUST_MIN_STACK", "8388608")
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "isolated {what} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    false
}
