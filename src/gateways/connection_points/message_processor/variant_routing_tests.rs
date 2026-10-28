//! How Fabric receive serves and refuses a forwarded request by the surface
//! variant it selects on this gateway.

use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::{Value, json};

use super::{ProcessingResult, process_forward_request};
use crate::audit::request_events::{RejectionReason, RejectionStage};
use crate::component_tests::helpers::MockServer;
use crate::config::agent_surface::AgentSurface;
use crate::delegation_vault::audit::{DelegationAuditAction, DelegationAuditEvent};
use crate::gateways::connection_points::messages::{MessageMetadata, ReceivedMessage};
use crate::gateways::types::{ExposureMode, Gateway, GatewayType};
use crate::messages::MessageType;
use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};

const SENDER_DID: &str = "did:web:sender.example";

pub(super) struct Receiver {
    pub target: MockServer,
    storage_path: std::path::PathBuf,
    _root: tempfile::TempDir,
    _issuer_dir: tempfile::TempDir,
}

impl Receiver {
    /// A receiving gateway with one paired sender and the given surfaces, each
    /// targeting the same upstream.
    pub async fn new(surfaces: &[(&str, Value, Option<&str>)]) -> Self {
        let target = MockServer::start_with_response(
            json!({"jsonrpc": "2.0", "id": "variant", "result": {"tools": []}}).to_string(),
        )
        .await;
        let root = tempfile::tempdir().unwrap();
        let mut sender =
            Gateway::new(SENDER_DID.to_string(), String::new(), SENDER_DID.to_string(), GatewayType::Remote);
        sender.exposure_mode = Some(ExposureMode::All);
        sender.issuer_did = Some("did:web:sender-gateway.example".to_string());
        let issuer_dir =
            crate::gateways::test_helpers::install_listener_manager_with_peers(root.path(), &[sender]).await;
        let storage_path = root
            .path()
            .join("surfaces");
        let store = FileSystemAgentSurfaceStore::new(storage_path.clone())
            .await
            .unwrap();
        for (surface_id, variants, default_variant_id) in surfaces {
            let surface: AgentSurface = serde_json::from_value(json!({
                "surface_id": surface_id, "name": surface_id,
                "access_point": {"listen_address": "127.0.0.1:8080", "route": format!("/{surface_id}"), "protocol": "mcp"},
                "target": {"endpoint": format!("http://{}", target.addr)},
                "variants": variants,
                "default_variant_id": default_variant_id
            }))
            .unwrap();
            store
                .save(&surface)
                .await
                .unwrap();
        }
        Self {
            target,
            storage_path,
            _root: root,
            _issuer_dir: issuer_dir,
        }
    }

    /// A legacy `ForwardRequest` for `surface_id`, naming `alias` the way
    /// the sending gateway does.
    pub fn forward_request(
        &self,
        surface_id: &str,
        alias: Option<&str>,
    ) -> ReceivedMessage {
        self.forward_request_with_body(
            surface_id,
            alias,
            json!({"jsonrpc": "2.0", "id": "variant", "method": "tools/list"}),
        )
    }

    pub fn forward_request_with_body(
        &self,
        surface_id: &str,
        alias: Option<&str>,
        request_body: Value,
    ) -> ReceivedMessage {
        let mut body = json!({
            "channel_id": surface_id,
            "method": "POST",
            "path": "/",
            "trace_id": "0af7651916cd43dd8448eb211c80319c",
            "headers": {"MCP-Protocol-Version": crate::mcp::MCP_LEGACY_VERSION, "content-type": "application/json"},
            "body": request_body
        });
        if let Some(alias) = alias {
            body["active_variant_alias"] = json!(alias);
        }
        ReceivedMessage::new(
            "receiver-connection".to_string(),
            "receiver-gateway".to_string(),
            MessageType::ForwardRequest.to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            Some(SENDER_DID.to_string()),
            vec!["did:web:receiver.example".to_string()],
            None,
            Some(super::super::envelope_replay::now_secs() + 60),
            body,
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: Value::Null,
            },
        )
        .with_context("agent_surface_storage_path", json!(self.storage_path))
    }

    /// Processes `message` and returns the `ForwardResponse` status with every
    /// audit record the request wrote.
    pub async fn receive(
        &self,
        message: &ReceivedMessage,
    ) -> (u64, Vec<DelegationAuditEvent>) {
        let (result, events) = crate::audit::producer::capture(async {
            tokio::time::timeout(Duration::from_secs(10), Box::pin(process_forward_request(message)))
                .await
                .expect("Fabric receive handler timed out")
        })
        .await;
        let ProcessingResult::RequiresResponse { response_body, .. } = result else {
            panic!("expected a ForwardResponse, got {result:?}");
        };
        (
            response_body["status"]
                .as_u64()
                .unwrap_or_else(|| panic!("no status in {response_body}")),
            events,
        )
    }
}

pub(super) fn catalog() -> Value {
    json!([
        {"id": "v-prod", "alias": "prod", "name": "Prod"},
        {"id": "v-beta", "alias": "beta", "name": "Beta"},
        {"id": "v-off", "alias": "off", "name": "Off", "enabled": false}
    ])
}

fn refusals(
    events: &[DelegationAuditEvent]
) -> Vec<(RejectionStage, RejectionReason, Option<u16>, Option<String>, bool)> {
    events
        .iter()
        .filter_map(|event| match &event.event {
            DelegationAuditAction::RequestRejected {
                stage,
                reason,
                http_status,
                requested_variant,
                ..
            } => Some((*stage, *reason, *http_status, requested_variant.clone(), event.via_fabric)),
            _ => None,
        })
        .collect()
}

/// Runs `test` in a child process: Fabric receive reads process-wide globals
/// (the listener manager) that other tests also install.
pub(super) fn isolated(
    variable: &str,
    test: impl std::future::Future<Output = ()>,
) {
    if std::env::var_os(variable).is_none() {
        let test_name = std::thread::current()
            .name()
            .expect("test thread name")
            .to_string();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env(variable, "1")
            .output()
            .expect("run the Fabric receive test with isolated globals");
        assert!(
            output.status.success(),
            "isolated Fabric receive test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(test);
}

#[test]
fn fabric_receive_refuses_a_variant_it_cannot_resolve_without_calling_the_upstream() {
    isolated("AG_FABRIC_VARIANT_REFUSAL_CHILD", async {
        let receiver = Receiver::new(&[
            ("variants", catalog(), Some("v-prod")),
            ("dangling", json!([]), Some("removed")),
            ("dangling-variants", catalog(), Some("removed")),
        ])
        .await;
        let routing = |reason, requested: Option<&str>| {
            vec![(RejectionStage::Routing, reason, None, requested.map(str::to_string), true)]
        };
        for (case, surface_id, alias, status_answered, expected) in [
            (
                "unknown alias",
                "variants",
                Some("missing"),
                404,
                routing(RejectionReason::UnknownVariant, Some("missing")),
            ),
            ("disabled alias", "variants", Some("off"), 404, routing(RejectionReason::VariantDisabled, None)),
            (
                "misconfigured default with no variants",
                "dangling",
                None,
                500,
                routing(RejectionReason::MisconfiguredDefault, None),
            ),
            (
                "misconfigured default with variants",
                "dangling-variants",
                None,
                500,
                routing(RejectionReason::MisconfiguredDefault, None),
            ),
        ] {
            let (status, events) = receiver
                .receive(&receiver.forward_request(surface_id, alias))
                .await;
            assert_eq!(status, status_answered, "{case}: status");
            assert_eq!(refusals(&events), expected, "{case}: recorded refusal, with no HTTP status on Fabric");
        }
        assert_eq!(
            receiver
                .target
                .request_count
                .load(Ordering::SeqCst),
            0,
            "no refused request reaches the upstream"
        );

        let (status, events) = receiver
            .receive(&receiver.forward_request("variants", Some("beta")))
            .await;
        assert_eq!(status, 200, "{events:?}");
        assert!(refusals(&events).is_empty());

        let variants = |events: &[DelegationAuditEvent]| {
            events
                .iter()
                .map(|event| event.surface_variant.clone())
                .collect::<Vec<_>>()
        };
        let (_, events) = receiver
            .receive(&receiver.forward_request("variants", Some("missing")))
            .await;
        assert_eq!(variants(&events), vec![Some("_unknown_".to_string())]);
        let (_, events) = receiver
            .receive(&receiver.forward_request("variants", Some("off")))
            .await;
        assert_eq!(variants(&events), vec![Some("off".to_string())]);
        let (_, events) = receiver
            .receive(&receiver.forward_request("dangling", None))
            .await;
        assert_eq!(variants(&events), vec![None]);
    });
}

#[test]
fn every_fabric_receive_record_names_this_gateways_variant() {
    isolated("AG_FABRIC_VARIANT_RECORD_CHILD", async {
        let receiver = Receiver::new(&[
            ("defaulted", catalog(), Some("v-prod")),
            ("plain", json!([]), None),
        ])
        .await;
        for (case, surface_id, alias, expected) in [
            ("the alias the sender named", "defaulted", Some("beta"), "beta"),
            ("no alias, this surface's default variant", "defaulted", None, "prod"),
            ("no alias, a surface with no variants", "plain", None, "_base_"),
        ] {
            let message = receiver.forward_request_with_body(surface_id, alias, json!("not a JSON-RPC request"));
            let ((_, events), spans) =
                crate::observability::http_trace::span_capture::capture_spans(receiver.receive(&message)).await;
            assert!(!events.is_empty(), "{case}: the request writes records");
            for event in &events {
                assert_eq!(event.surface_variant.as_deref(), Some(expected), "{case}: {event:?}");
            }
            let request_span = spans
                .iter()
                .find(|span| span.name == "fabric.forward_request")
                .unwrap_or_else(|| panic!("{case}: the fabric request span was exported"));
            assert_eq!(
                crate::observability::http_trace::span_capture::span_attr(request_span, "surface.variant").as_deref(),
                Some(expected),
                "{case}"
            );
        }
    });
}
