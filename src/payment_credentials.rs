//! Payment dispute-evidence Verifiable Credentials.
//!
//! Promotes the terminal payment lifecycle stages (`verified`/`settled` →
//! receipt, `failed`/`settlement_failed` → rejection; a Model B delegated
//! `proceed` → access grant) to a signed, portable credential — independent
//! evidence a dispute arbiter can verify without trusting either party's
//! private audit log. Opt-in via the `payment_receipt_vc` feature flag
//! (Settings) so no signing overhead is incurred unless enabled; issuance
//! never blocks or fails a payment (every function returns `None` on any
//! error).

use std::sync::{Arc, OnceLock};

use serde::Serialize;

use crate::identity::VCIssuer;

static GLOBAL_VC_ISSUER: OnceLock<Arc<VCIssuer>> = OnceLock::new();

/// Register the gateway's `VCIssuer` for payment-credential issuance. Called
/// once from the orchestrator, alongside its other global registrations.
pub fn set_global_payment_vc_issuer(issuer: Arc<VCIssuer>) {
    let _ = GLOBAL_VC_ISSUER.set(issuer);
}

fn global_payment_vc_issuer() -> Option<Arc<VCIssuer>> {
    GLOBAL_VC_ISSUER
        .get()
        .cloned()
}

/// Whether payment dispute-evidence VC issuance is enabled
/// (`feature_flags["payment_receipt_vc"]` in dashboard settings). Defaults to
/// off so existing deployments see no behavior change.
fn payment_receipt_vc_enabled() -> bool {
    crate::storage::settings_store::global_settings()
        .map(|s| {
            s.feature_flags
                .get("payment_receipt_vc")
                .copied()
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// On-chain / processor settlement evidence embedded in a receipt once funds
/// have moved.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SettlementEvidence {
    #[serde(rename = "txHash", skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmations: Option<u64>,
}

/// Input to [`issue_payment_receipt`]. Every optional field is included in
/// `credentialSubject` only when present, so a provisional (`verified`, not
/// yet `settled`) receipt is smaller than the final, settlement-augmented one.
#[derive(Debug, Clone, Default)]
pub struct PaymentReceiptInput {
    pub rail: &'static str,
    pub payment_id: String,
    pub trace_id: Option<String>,
    pub amount: Option<String>,
    pub currency: Option<String>,
    pub method: Option<String>,
    pub payer: Option<String>,
    pub resource: Option<String>,
    pub settled: bool,
    pub settlement: Option<SettlementEvidence>,
    /// The payer's own signed authorization (x402 EIP-3009/Permit2 signature),
    /// embedded so the receipt is bilaterally provable, not merely
    /// self-attested by the issuing gateway.
    pub payer_signature: Option<String>,
}

/// Input to [`issue_payment_rejection`].
#[derive(Debug, Clone, Default)]
pub struct PaymentRejectionInput {
    pub rail: &'static str,
    pub payment_id: String,
    pub trace_id: Option<String>,
    pub method: Option<String>,
    pub payer: Option<String>,
    pub reason: String,
}

/// Input to [`issue_access_grant`] — the delegated (Model B) counterpart to a
/// receipt: agent-gateway is the relying/access party, not the money mover, so
/// it attests to granting access on a payment it relayed to a remote payment
/// gateway rather than to settlement itself.
#[derive(Debug, Clone, Default)]
pub struct AccessGrantInput {
    pub rail: &'static str,
    pub trace_id: Option<String>,
    pub payment_gateway_id: Option<String>,
    pub payment_surface_id: Option<String>,
    pub remote_status: u16,
}

#[derive(Debug, Clone, Serialize)]
struct ReceiptSubject {
    #[serde(rename = "paymentId")]
    payment_id: String,
    rail: &'static str,
    stage: &'static str,
    #[serde(rename = "traceId", skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    settlement: Option<SettlementEvidence>,
}

#[derive(Debug, Clone, Serialize)]
struct RejectionSubject {
    #[serde(rename = "paymentId")]
    payment_id: String,
    rail: &'static str,
    #[serde(rename = "traceId", skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payer: Option<String>,
    reason: String,
}

#[derive(Debug, Clone, Serialize)]
struct AccessGrantSubject {
    rail: &'static str,
    #[serde(rename = "traceId", skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
    remote: AccessGrantRemote,
}

#[derive(Debug, Clone, Serialize)]
struct AccessGrantRemote {
    #[serde(rename = "gatewayId", skip_serializing_if = "Option::is_none")]
    gateway_id: Option<String>,
    #[serde(rename = "surfaceId", skip_serializing_if = "Option::is_none")]
    surface_id: Option<String>,
    #[serde(rename = "status")]
    status: u16,
}

/// A minted credential + its fingerprint, ready to persist on the transaction
/// record and stamp onto the corresponding payment audit event via
/// `record_payment_event`'s `vc_jwt` parameter.
#[derive(Debug, Clone)]
pub struct IssuedCredential {
    pub jwt: String,
    pub fingerprint: String,
}

async fn sign_credential(
    vc_type: &str,
    subject: impl Serialize,
) -> Option<IssuedCredential> {
    let issuer = global_payment_vc_issuer()?;
    let issuer_did = issuer
        .get_issuer_did()
        .await
        .ok()?;
    let subject_value = serde_json::to_value(subject).ok()?;
    let claims = serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", vc_type],
        "issuer": issuer_did,
        "issuanceDate": chrono::Utc::now().to_rfc3339(),
        "credentialSubject": subject_value,
        "jti": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
    });
    let jwt = issuer
        .sign_jwt_with_gateway_key(&claims)
        .await
        .ok()?;
    let fingerprint = crate::delegation_vault::audit::vp_fingerprint(&jwt);
    Some(IssuedCredential { jwt, fingerprint })
}

/// Issue (or re-issue, at settlement) a `PaymentReceiptCredential`. Returns
/// `None` when the feature is disabled, no gateway `VCIssuer` is registered,
/// or signing fails — a payment is never blocked on VC issuance.
pub async fn issue_payment_receipt(input: PaymentReceiptInput) -> Option<IssuedCredential> {
    if !payment_receipt_vc_enabled() {
        return None;
    }
    let mut subject = serde_json::to_value(ReceiptSubject {
        payment_id: input.payment_id,
        rail: input.rail,
        stage: if input.settled {
            "settled"
        } else {
            "verified"
        },
        trace_id: input.trace_id,
        amount: input.amount,
        currency: input.currency,
        method: input.method,
        payer: input.payer,
        resource: input.resource,
        settlement: input.settlement,
    })
    .ok()?;
    if let Some(sig) = input.payer_signature
        && let Some(obj) = subject.as_object_mut()
    {
        obj.insert("payerSignature".to_string(), serde_json::Value::String(sig));
    }
    sign_credential("PaymentReceiptCredential", subject).await
}

/// Issue a `PaymentRejectionCredential` for a failed verification or a
/// settlement that failed after a successful verification.
pub async fn issue_payment_rejection(input: PaymentRejectionInput) -> Option<IssuedCredential> {
    if !payment_receipt_vc_enabled() {
        return None;
    }
    sign_credential(
        "PaymentRejectionCredential",
        RejectionSubject {
            payment_id: input.payment_id,
            rail: input.rail,
            trace_id: input.trace_id,
            method: input.method,
            payer: input.payer,
            reason: input.reason,
        },
    )
    .await
}

/// Issue a `PaymentAccessGrantCredential` for a Model B delegated payment this
/// gateway authorised to proceed. agent-gateway is the relying/access party
/// here, not the money mover, so this attests to *granting access* on a
/// payment relayed to `payment_gateway_id`/`payment_surface_id` — it does not
/// assert settlement, which is the remote payment gateway's own responsibility
/// to attest to (via its own receipt credential, correlated by `trace_id`).
pub async fn issue_access_grant(input: AccessGrantInput) -> Option<IssuedCredential> {
    if !payment_receipt_vc_enabled() {
        return None;
    }
    sign_credential(
        "PaymentAccessGrantCredential",
        AccessGrantSubject {
            rail: input.rail,
            trace_id: input.trace_id,
            remote: AccessGrantRemote {
                gateway_id: input.payment_gateway_id,
                surface_id: input.payment_surface_id,
                status: input.remote_status,
            },
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_subject_omits_absent_optionals_and_reports_stage_from_settled() {
        let provisional = ReceiptSubject {
            payment_id: "txn-1".to_string(),
            rail: "x402",
            stage: "verified",
            trace_id: None,
            amount: None,
            currency: None,
            method: None,
            payer: None,
            resource: None,
            settlement: None,
        };
        let json = serde_json::to_value(&provisional).unwrap();
        assert_eq!(json["paymentId"], "txn-1");
        assert_eq!(json["stage"], "verified");
        assert!(json.get("traceId").is_none());
        assert!(
            json.get("settlement")
                .is_none()
        );

        let settled = ReceiptSubject {
            stage: "settled",
            settlement: Some(SettlementEvidence {
                tx_hash: Some("0xabc".to_string()),
                network: Some("eip155:1".to_string()),
                confirmations: Some(3),
            }),
            ..provisional
        };
        let json = serde_json::to_value(&settled).unwrap();
        assert_eq!(json["stage"], "settled");
        assert_eq!(json["settlement"]["txHash"], "0xabc");
        assert_eq!(json["settlement"]["confirmations"], 3);
    }

    #[test]
    fn rejection_subject_always_carries_reason() {
        let subject = RejectionSubject {
            payment_id: "txn-2".to_string(),
            rail: "mpp",
            trace_id: Some("trace-1".to_string()),
            method: None,
            payer: None,
            reason: "invalid signature".to_string(),
        };
        let json = serde_json::to_value(&subject).unwrap();
        assert_eq!(json["rail"], "mpp");
        assert_eq!(json["traceId"], "trace-1");
        assert_eq!(json["reason"], "invalid signature");
        assert!(json.get("method").is_none());
    }

    #[test]
    fn access_grant_subject_nests_remote_fields() {
        let subject = AccessGrantSubject {
            rail: "x402",
            trace_id: Some("trace-2".to_string()),
            remote: AccessGrantRemote {
                gateway_id: Some("gw-pay".to_string()),
                surface_id: Some("pay-ch".to_string()),
                status: 200,
            },
        };
        let json = serde_json::to_value(&subject).unwrap();
        assert_eq!(json["remote"]["gatewayId"], "gw-pay");
        assert_eq!(json["remote"]["surfaceId"], "pay-ch");
        assert_eq!(json["remote"]["status"], 200);
    }

    #[tokio::test]
    async fn issuance_returns_none_without_settings_or_issuer() {
        // Neither a global settings store nor a VCIssuer is registered in a
        // bare unit-test process, so every issuance path must fail closed to
        // `None` rather than panicking or blocking a payment.
        let receipt = issue_payment_receipt(PaymentReceiptInput {
            rail: "x402",
            payment_id: "txn-3".to_string(),
            ..Default::default()
        })
        .await;
        assert!(receipt.is_none());

        let rejection = issue_payment_rejection(PaymentRejectionInput {
            rail: "x402",
            payment_id: "txn-3".to_string(),
            reason: "denied".to_string(),
            ..Default::default()
        })
        .await;
        assert!(rejection.is_none());

        let grant = issue_access_grant(AccessGrantInput {
            rail: "x402",
            remote_status: 200,
            ..Default::default()
        })
        .await;
        assert!(grant.is_none());
    }
}
