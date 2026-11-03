//! How Fabric receive refuses a request to a surface whose Target is bound by
//! external consent.

use std::sync::atomic::Ordering;

use serde_json::json;

use super::variant_routing_tests::{Receiver, isolated};

/// A request that arrived over Fabric for a surface whose Target is bound by
/// external consent is refused as one whose caller the gateway did not
/// identify before any payment is asked for or settled, so a Fabric caller
/// never pays for a request no grant can serve.
#[test]
fn fabric_receive_refuses_a_bound_target_before_payment() {
    isolated("AG_FABRIC_TARGET_GRANT_PAYMENT_CHILD", async {
        let receiver = Receiver::serving(|target| {
            vec![json!({
                "surface_id": "paid-vendor", "name": "paid-vendor",
                "access_point": {"listen_address": "127.0.0.1:8080", "route": "/paid-vendor", "protocol": "mcp"},
                "target": {"endpoint": format!("{target}/mcp"), "payment_policy": {
                    "type": "x402", "enabled": true, "verification_mode": "mock", "settlement_mode": "none",
                    "payment_requirements": [{"scheme": "exact", "network": "eip155:1", "amount": "1000",
                        "asset": "0x123", "payTo": "0x456", "maxTimeoutSeconds": 300}],
                    "mcp_payment_triggers": {"mode": "all"}}},
                "outbound_credentials": [{"credential_provider_id": "vendor", "consent_mode": "external",
                    "subject": "owner"}]
            })]
        })
        .await;
        let call = json!({"jsonrpc": "2.0", "id": "paid", "method": "tools/call",
            "params": {"name": "search", "arguments": {}}});
        let (status, events) = receiver
            .receive(&receiver.forward_request_with_body("paid-vendor", None, call))
            .await;
        assert_eq!(status, 403, "{events:?}");
        assert_eq!(
            receiver
                .target
                .request_count
                .load(Ordering::SeqCst),
            0
        );
    });
}

/// A public discovery read that arrived over Fabric for a surface whose
/// Target is bound by external consent is refused too, so the peer's headers,
/// its caller's cookies among them, never reach the vendor, and the vendor's
/// `Set-Cookie` never reaches the peer: no request over Fabric can use such a
/// Target, so nothing needs its discovery there.
#[test]
fn fabric_receive_refuses_a_discovery_read_of_a_bound_target() {
    isolated("AG_FABRIC_TARGET_GRANT_DISCOVERY_CHILD", async {
        let receiver = Receiver::serving(|target| {
            vec![json!({
                "surface_id": "vendor", "name": "vendor",
                "access_point": {"listen_address": "127.0.0.1:8080", "route": "/vendor", "protocol": "a2a"},
                "target": {"endpoint": format!("{target}/a2a")},
                "outbound_credentials": [{"credential_provider_id": "vendor", "consent_mode": "external",
                    "subject": "owner"}]
            })]
        })
        .await;
        for path in ["/.well-known/agent-card.json", "/discovery", "/.well-known/ucp"] {
            let mut message = receiver.forward_request_with_body("vendor", None, json!(null));
            message.message_body["method"] = json!("GET");
            message.message_body["path"] = json!(path);
            message.message_body["body"] = json!(null);
            message.message_body["headers"] =
                json!({"cookie": "session_token=dashboard-session", "accept": "application/json"});
            let (status, events) = receiver
                .receive(&message)
                .await;
            assert_eq!(status, 403, "{path}: {events:?}");
        }
        assert_eq!(
            receiver
                .target
                .request_count
                .load(Ordering::SeqCst),
            0
        );
    });
}
