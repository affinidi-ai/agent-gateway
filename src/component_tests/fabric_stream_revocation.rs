//! Revoking a peer's access ends its running Fabric streams: a peer that
//! leaves active, a surface its record stops exposing, and a disabled
//! Connection Point each end only the streams they cover.

use crate::gateways::connection_points::ConnectionPointStore;
use crate::gateways::connection_points::types::{ConnectionPointType, GatewayConnectionPoint};
use crate::gateways::types::{ExposureMode, Gateway, GatewayStatus, GatewayType};
use crate::gateways::{FileSystemConnectionPointStore, FileSystemGatewayStore, GatewayStore};
use crate::proxy::fabric_stream::peer::StreamCapabilities;
use crate::proxy::fabric_stream::registry::{ReceiveLease, SendLease, StreamBinding, StreamKind};
use crate::proxy::fabric_stream::wire::{MAX_CHUNK_BYTES, StreamDirection, StreamErrorCode};

const CHILD: &str = "ATG_FABRIC_STREAM_REVOCATION_CHILD";

/// A registered stream, held open by its two leases.
struct Running {
    receiver: ReceiveLease,
    sender: SendLease,
}

impl Running {
    /// A stream `peer_did` opened here, through `connection_point_id`, to the
    /// local `surface_id`.
    fn inbound(
        peer_did: &str,
        connection_point_id: &str,
        surface_id: &str,
    ) -> Self {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        let (receiver, sender) = registry()
            .open(
                uuid::Uuid::new_v4(),
                binding(peer_did, connection_point_id, surface_id),
                MAX_CHUNK_BYTES,
                MAX_CHUNK_BYTES,
                deadline,
            )
            .unwrap();
        Self { receiver, sender }
    }

    /// A stream this gateway opened to `peer_did`'s channel.
    fn outbound(
        peer_did: &str,
        connection_point_id: &str,
    ) -> Self {
        let stream_id = uuid::Uuid::new_v4();
        let capabilities = StreamCapabilities::local(true, true);
        let binding = binding(peer_did, connection_point_id, "peer-channel");
        let receiver = registry()
            .register_negotiated(
                stream_id,
                binding.clone(),
                StreamKind::Request,
                StreamDirection::Response,
                MAX_CHUNK_BYTES,
                &capabilities,
            )
            .unwrap();
        let sender = registry()
            .register_sender_negotiated(
                stream_id,
                binding,
                StreamKind::Request,
                StreamDirection::Request,
                MAX_CHUNK_BYTES,
                &capabilities,
            )
            .unwrap();
        Self { receiver, sender }
    }

    /// The code each side ended with, `None` while it runs.
    fn ended_with(&self) -> (Option<StreamErrorCode>, Option<StreamErrorCode>) {
        (
            *self
                .receiver
                .closed()
                .borrow(),
            *self
                .sender
                .credit()
                .cancellation()
                .borrow(),
        )
    }

    fn assert_ended(
        &self,
        context: &str,
    ) {
        assert_eq!(
            self.ended_with(),
            (Some(StreamErrorCode::Unavailable), Some(StreamErrorCode::Unavailable)),
            "{context}"
        );
    }

    fn assert_running(
        &self,
        context: &str,
    ) {
        assert_eq!(self.ended_with(), (None, None), "{context}");
    }
}

fn registry() -> &'static std::sync::Arc<crate::proxy::fabric_stream::registry::ReceiveRegistry> {
    &crate::proxy::fabric_stream::global()
        .unwrap()
        .registry
}

fn binding(
    peer_did: &str,
    connection_point_id: &str,
    surface_id: &str,
) -> StreamBinding {
    StreamBinding {
        peer_did: peer_did.into(),
        recipient_did: "did:example:local".into(),
        connection_point_id: connection_point_id.into(),
        listener_instance_id: "instance".into(),
        surface_id: surface_id.into(),
    }
}

fn remote(
    name: &str,
    mode: ExposureMode,
    surfaces: &[&str],
) -> Gateway {
    let mut gateway = Gateway::new(name.into(), String::new(), format!("did:example:{name}"), GatewayType::Remote);
    gateway.status = GatewayStatus::Active;
    gateway.exposure_mode = Some(mode);
    gateway.exposed_channels = surfaces
        .iter()
        .map(|surface| surface.to_string())
        .collect();
    gateway
}

fn connection_point(name: &str) -> GatewayConnectionPoint {
    GatewayConnectionPoint::new(
        "gateway".into(),
        "mediator".into(),
        format!("did:example:{name}"),
        name.into(),
        String::new(),
        format!("oob-{name}"),
        String::new(),
        serde_json::json!({}),
        None,
        ConnectionPointType::User,
        String::new(),
    )
}

/// Runs the calling test alone in a child process, as revocation acts on the
/// process-wide stream registry. Returns true inside the child.
async fn in_isolated_child() -> bool {
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    let test_name = std::thread::current()
        .name()
        .unwrap()
        .to_string();
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test_name, "--nocapture"])
        .env(CHILD, "1")
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "isolated stream revocation test failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

#[tokio::test]
async fn a_peer_that_leaves_active_ends_its_streams_in_both_directions() {
    if !in_isolated_child().await {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let gateways = FileSystemGatewayStore::new(
        directory
            .path()
            .join("gateways"),
        None,
    )
    .await
    .unwrap();
    let alpha = remote("alpha", ExposureMode::All, &[]);
    let bravo = remote("bravo", ExposureMode::All, &[]);
    for gateway in [&alpha, &bravo] {
        gateways
            .create(gateway)
            .await
            .unwrap();
    }
    let alpha_inbound = Running::inbound(&alpha.did, "cp-one", "surface-x");
    let alpha_outbound = Running::outbound(&alpha.did, "cp-one");
    let bravo_inbound = Running::inbound(&bravo.did, "cp-two", "surface-x");
    let bravo_outbound = Running::outbound(&bravo.did, "cp-two");

    let mut disabled = alpha.clone();
    disabled.status = GatewayStatus::Disabled;
    gateways
        .update(&disabled)
        .await
        .unwrap();
    alpha_inbound.assert_ended("a stream the disabled peer opened here");
    alpha_outbound.assert_ended("a stream this gateway opened to the disabled peer");
    bravo_inbound.assert_running("another peer's inbound stream");
    bravo_outbound.assert_running("another peer's outbound stream");

    gateways
        .delete(&bravo.id)
        .await
        .unwrap();
    bravo_inbound.assert_ended("a stream the removed peer opened here");
    bravo_outbound.assert_ended("a stream this gateway opened to the removed peer");
}

#[tokio::test]
async fn narrowing_a_peers_exposure_ends_only_its_streams_to_surfaces_it_lost() {
    if !in_isolated_child().await {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let gateways = FileSystemGatewayStore::new(
        directory
            .path()
            .join("gateways"),
        None,
    )
    .await
    .unwrap();
    let alpha = remote("alpha", ExposureMode::List, &["surface-x", "surface-y"]);
    let bravo = remote("bravo", ExposureMode::List, &["surface-x"]);
    for gateway in [&alpha, &bravo] {
        gateways
            .create(gateway)
            .await
            .unwrap();
    }
    let alpha_to_x = Running::inbound(&alpha.did, "cp-one", "surface-x");
    let alpha_to_y = Running::inbound(&alpha.did, "cp-one", "surface-y");
    let alpha_outbound = Running::outbound(&alpha.did, "cp-one");
    let bravo_to_x = Running::inbound(&bravo.did, "cp-two", "surface-x");

    let mut renamed = alpha.clone();
    renamed.name = "alpha, renamed".into();
    let revocations = registry().revocations();
    gateways
        .update(&renamed)
        .await
        .unwrap();
    assert_eq!(registry().revocations(), revocations, "a change that keeps the exposure revokes nothing");
    alpha_to_x.assert_running("an update that keeps the exposure");

    let mut narrowed = renamed.clone();
    narrowed.exposed_channels = vec!["surface-y".into()];
    gateways
        .update(&narrowed)
        .await
        .unwrap();
    alpha_to_x.assert_ended("the peer's stream to the surface it lost");
    alpha_to_y.assert_running("the peer's stream to a surface it keeps");
    alpha_outbound.assert_running("a stream this gateway opened to the peer");
    bravo_to_x.assert_running("another peer's stream to the same surface");

    let mut closed = narrowed.clone();
    closed.exposure_mode = Some(ExposureMode::None);
    gateways
        .update(&closed)
        .await
        .unwrap();
    alpha_to_y.assert_ended("the peer's last stream once its mode is none");
    alpha_outbound.assert_running("a stream this gateway opened to the peer");
    bravo_to_x.assert_running("another peer's stream");
}

#[tokio::test]
async fn disabling_a_connection_point_ends_only_the_streams_it_carries() {
    if !in_isolated_child().await {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let connection_points = FileSystemConnectionPointStore::new(
        directory
            .path()
            .join("connection_points"),
    )
    .await
    .unwrap();
    let one = connection_point("one");
    let mut two = connection_point("two");
    two.exposed_channels = vec!["surface-x".into(), "surface-y".into()];
    for connection_point in [&one, &two] {
        connection_points
            .create(connection_point)
            .await
            .unwrap();
    }
    let inbound_on_one = Running::inbound("did:example:alpha", &one.id, "surface-x");
    let outbound_on_one = Running::outbound("did:example:alpha", &one.id);
    let x_on_two = Running::inbound("did:example:alpha", &two.id, "surface-x");
    let y_on_two = Running::inbound("did:example:bravo", &two.id, "surface-y");

    let mut disabled = one.clone();
    disabled.enabled = false;
    connection_points
        .update(&disabled)
        .await
        .unwrap();
    inbound_on_one.assert_ended("an inbound stream the disabled Connection Point carried");
    outbound_on_one.assert_ended("an outbound stream the disabled Connection Point carried");
    x_on_two.assert_running("a stream on another Connection Point");
    y_on_two.assert_running("a stream on another Connection Point");

    let mut narrowed = two.clone();
    narrowed.exposed_channels = vec!["surface-y".into()];
    connection_points
        .update(&narrowed)
        .await
        .unwrap();
    x_on_two.assert_ended("a stream to a surface the Connection Point stopped exposing");
    y_on_two.assert_running("a stream to a surface the Connection Point still exposes");

    connection_points
        .delete(&two.id)
        .await
        .unwrap();
    y_on_two.assert_ended("a stream the removed Connection Point carried");
}
