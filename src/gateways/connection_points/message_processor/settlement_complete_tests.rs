//! A settlement-complete message completes a legacy x402 transaction only when
//! it comes from that transaction's active facilitator gateway and reports
//! `completed`.

use serde_json::json;

use super::apply_settlement_complete;
use crate::gateways::connection_points::messages::{MessageMetadata, ReceivedMessage};
use crate::gateways::types::{Gateway, GatewayStatus, GatewayType};
use crate::gateways::{FileSystemGatewayStore, GatewayStore};
use crate::messages::MessageType;
use crate::x402::TransactionStore;
use crate::x402::transaction_store::{SettlementStatus, X402Transaction};

const CORRELATION_ID: &str = "correlation-1";
const FACILITATOR_DID: &str = "did:web:facilitator.example";
const OTHER_PEER_DID: &str = "did:web:other-peer.example";

struct Fixture {
    _root: tempfile::TempDir,
    transactions: TransactionStore,
    gateways: FileSystemGatewayStore,
    facilitator: Gateway,
}

async fn peer(
    gateways: &FileSystemGatewayStore,
    did: &str,
    status: GatewayStatus,
) -> Gateway {
    let mut gateway = Gateway::new("Peer".to_string(), String::new(), did.to_string(), GatewayType::Remote);
    gateway.status = status;
    gateways
        .create(&gateway)
        .await
        .unwrap();
    gateway
}

async fn fixture(facilitator_status: GatewayStatus) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let gateways = FileSystemGatewayStore::new(root.path().join("gateways"), None)
        .await
        .unwrap();
    let facilitator = peer(&gateways, FACILITATOR_DID, facilitator_status).await;
    peer(&gateways, OTHER_PEER_DID, GatewayStatus::Active).await;

    let transactions = TransactionStore::new(root.path().join("x402"))
        .await
        .unwrap();
    let payload = serde_json::from_value(json!({
        "x402Version": 2,
        "accepted": {
            "scheme": "exact",
            "network": "eip155:1",
            "amount": "1000",
            "asset": "0x123",
            "payTo": "0x456",
            "maxTimeoutSeconds": 300
        },
        "payload": { "signature": "0xsig" }
    }))
    .unwrap();
    transactions
        .insert(
            X402Transaction::new(
                CORRELATION_ID.to_string(),
                "surface-1".to_string(),
                "Surface".to_string(),
                "/".to_string(),
                payload,
                "FabricGateway".to_string(),
                Some(facilitator.id.clone()),
            )
            .with_settlement(SettlementStatus::Pending, "fabric_gateway"),
        )
        .await;

    Fixture {
        _root: root,
        transactions,
        gateways,
        facilitator,
    }
}

fn settlement_complete(
    from_did: Option<&str>,
    body: serde_json::Value,
) -> ReceivedMessage {
    ReceivedMessage::new(
        "cp-test".to_string(),
        "gw-test".to_string(),
        MessageType::X402SettlementComplete.to_string(),
        uuid::Uuid::new_v4().to_string(),
        None,
        from_did.map(str::to_string),
        vec!["did:web:receiver.example".to_string()],
        None,
        None,
        body,
        MessageMetadata {
            encrypted: true,
            authenticated: true,
            from_key: None,
            extra: serde_json::Value::Null,
        },
    )
}

fn completed_body() -> serde_json::Value {
    json!({ "correlation_id": CORRELATION_ID, "tx_hash": "0xsettled", "status": "completed" })
}

async fn settlement_of(fixture: &Fixture) -> (SettlementStatus, String) {
    let settlement = fixture
        .transactions
        .get(CORRELATION_ID)
        .await
        .unwrap()
        .settlement
        .unwrap();
    (settlement.status, settlement.tx_hash)
}

#[tokio::test]
async fn the_facilitator_gateway_completes_its_transaction() {
    let fixture = fixture(GatewayStatus::Active).await;

    let result = apply_settlement_complete(
        &settlement_complete(Some(FACILITATOR_DID), completed_body()),
        &fixture.transactions,
        &fixture.gateways,
    )
    .await;

    assert_eq!(result, Ok(()));
    assert_eq!(settlement_of(&fixture).await, (SettlementStatus::Completed, "0xsettled".to_string()));
}

#[tokio::test]
async fn another_peer_gateway_cannot_complete_the_transaction() {
    let fixture = fixture(GatewayStatus::Active).await;

    let result = apply_settlement_complete(
        &settlement_complete(Some(OTHER_PEER_DID), completed_body()),
        &fixture.transactions,
        &fixture.gateways,
    )
    .await;

    assert!(
        result
            .unwrap_err()
            .contains("not the active facilitator gateway")
    );
    assert_eq!(settlement_of(&fixture).await, (SettlementStatus::Pending, String::new()));
}

#[tokio::test]
async fn an_unregistered_or_missing_sender_cannot_complete_the_transaction() {
    let fixture = fixture(GatewayStatus::Active).await;

    for (from_did, reason) in
        [(Some("did:web:stranger.example"), "not the active facilitator gateway"), (None, "no sender DID")]
    {
        let result = apply_settlement_complete(
            &settlement_complete(from_did, completed_body()),
            &fixture.transactions,
            &fixture.gateways,
        )
        .await;

        assert!(
            result
                .unwrap_err()
                .contains(reason),
            "{from_did:?}"
        );
    }
    assert_eq!(settlement_of(&fixture).await, (SettlementStatus::Pending, String::new()));
}

#[tokio::test]
async fn a_disabled_facilitator_gateway_cannot_complete_the_transaction() {
    let fixture = fixture(GatewayStatus::Disabled).await;
    assert!(
        !fixture
            .facilitator
            .is_active()
    );

    let result = apply_settlement_complete(
        &settlement_complete(Some(FACILITATOR_DID), completed_body()),
        &fixture.transactions,
        &fixture.gateways,
    )
    .await;

    assert!(
        result
            .unwrap_err()
            .contains("not the active facilitator gateway")
    );
    assert_eq!(settlement_of(&fixture).await, (SettlementStatus::Pending, String::new()));
}

#[tokio::test]
async fn a_message_that_does_not_report_completed_changes_nothing() {
    let fixture = fixture(GatewayStatus::Active).await;

    for body in [
        json!({ "correlation_id": CORRELATION_ID, "tx_hash": "0xsettled" }),
        json!({ "correlation_id": CORRELATION_ID, "tx_hash": "0xsettled", "status": "failed" }),
    ] {
        let result = apply_settlement_complete(
            &settlement_complete(Some(FACILITATOR_DID), body),
            &fixture.transactions,
            &fixture.gateways,
        )
        .await;

        assert!(
            result
                .unwrap_err()
                .contains("not reported as completed")
        );
    }
    assert_eq!(settlement_of(&fixture).await, (SettlementStatus::Pending, String::new()));
}

#[tokio::test]
async fn an_unknown_transaction_is_refused() {
    let fixture = fixture(GatewayStatus::Active).await;

    let result = apply_settlement_complete(
        &settlement_complete(Some(FACILITATOR_DID), json!({ "correlation_id": "unknown", "status": "completed" })),
        &fixture.transactions,
        &fixture.gateways,
    )
    .await;

    assert!(
        result
            .unwrap_err()
            .contains("no transaction")
    );
}

#[tokio::test]
async fn a_repeated_settlement_complete_changes_nothing() {
    let fixture = fixture(GatewayStatus::Active).await;
    let complete = |tx_hash: &str| {
        settlement_complete(
            Some(FACILITATOR_DID),
            json!({ "correlation_id": CORRELATION_ID, "tx_hash": tx_hash, "status": "completed" }),
        )
    };
    apply_settlement_complete(&complete("0xsettled"), &fixture.transactions, &fixture.gateways)
        .await
        .unwrap();
    let first = fixture
        .transactions
        .get(CORRELATION_ID)
        .await
        .unwrap();

    let result = apply_settlement_complete(&complete("0xreplayed"), &fixture.transactions, &fixture.gateways).await;

    assert!(
        result
            .unwrap_err()
            .contains("not in progress")
    );
    let after = fixture
        .transactions
        .get(CORRELATION_ID)
        .await
        .unwrap();
    assert_eq!(settlement_of(&fixture).await, (SettlementStatus::Completed, "0xsettled".to_string()));
    assert_eq!(after.receipt_vc_jwt, first.receipt_vc_jwt);
    assert_eq!(after.last_updated, first.last_updated);
}

#[tokio::test]
async fn a_transaction_without_a_settlement_is_not_completed() {
    let fixture = fixture(GatewayStatus::Active).await;
    let mut unsettled = fixture
        .transactions
        .get(CORRELATION_ID)
        .await
        .unwrap();
    unsettled.id = "unsettled".to_string();
    unsettled.settlement = None;
    fixture
        .transactions
        .insert(unsettled)
        .await;

    let result = apply_settlement_complete(
        &settlement_complete(Some(FACILITATOR_DID), json!({ "correlation_id": "unsettled", "status": "completed" })),
        &fixture.transactions,
        &fixture.gateways,
    )
    .await;

    assert!(
        result
            .unwrap_err()
            .contains("not in progress")
    );
    let kept = fixture
        .transactions
        .get("unsettled")
        .await
        .unwrap();
    assert!(kept.settlement.is_none());
    assert_eq!(kept.receipt_vc_jwt, None);
}
